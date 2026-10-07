"""Packet/range-specific TLS-GCM randomization, before ordinary graph creation."""
import copy
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np

from recovery.application_audit import OUT, DATA, read
from recovery.application_integrity import verify
from recovery.capture_audit import load_samples, save, sha

VERSION = 'tls12-gcm-packet-range-pcg64-v1'
SEED = 32
TRANSFORMED = DATA / 'transformed_seed32'


def load_ranges():
    coverage = read(OUT / 'ciphertext_coverage.json')
    if sha(coverage['range_manifest']) != coverage['range_manifest_sha256']:
        raise ValueError('Ciphertext range manifest changed')
    with gzip.open(coverage['range_manifest'], 'rt') as handle:
        return json.load(handle)['samples']


def randomize(stored, capture_id, flow_id, packet, seed=SEED):
    """Only change audited ciphertext ranges in a copy of real retained bytes."""
    original = bytes(stored)
    if (len(original) != packet['retained_payload_bytes'] or
            len(original) != min(150, packet['payload_length']) or any(v > 255 for v in stored)):
        raise ValueError('Model-byte length or vocabulary differs from range audit')
    result = bytearray(original)
    ranges = sorted((r['start'], r['end']) for r in packet['ranges'] if r['kind'] == 'ciphertext')
    previous_end = 0
    for ordinal, (start, end) in enumerate(ranges):
        if not 0 <= start < end <= len(original) or start < previous_end:
            raise ValueError('Invalid/overlapping confirmed ciphertext range')
        identity = dict(version=VERSION, global_seed=seed, source_capture_id=capture_id, flow_id=flow_id,
                        packet_index_within_flow=packet['packet_index'], ciphertext_range_index=ordinal,
                        range_start=start, range_end=end)
        serialized = json.dumps(identity, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        digest = hashlib.sha256(serialized).digest()
        rng = np.random.default_rng(int.from_bytes(digest, 'big'))
        result[start:end] = rng.integers(0, 256, size=end - start, dtype=np.uint8).tobytes()
        previous_end = end
    allowed = {i for start, end in ranges for i in range(start, end)}
    if any(a != b and i not in allowed for i, (a, b) in enumerate(zip(original, result))):
        raise ValueError('STOP H: non-ciphertext byte changed')
    return list(result)


def transformed_samples(samples, ranges, seed=SEED):
    if len(samples) != len(ranges) or [s['id'] for s in samples] != [r['id'] for r in ranges]:
        raise ValueError('STOP K: range/sample membership differs')
    result, audit = [], []
    for sample, record in zip(samples, ranges):
        if sample['capture'] != record['capture'] or sample['label'] != record['label']:
            raise ValueError('STOP K: capture identity or label differs')
        if len(sample['payloads']) != len(record['packets']):
            raise ValueError('STOP K: packet counts differ')
        copied = copy.deepcopy(sample)
        for ordinal, (payload, packet) in enumerate(zip(sample['payloads'], record['packets'])):
            if packet['payload_ordinal'] != ordinal or packet['payload_length'] != sample['payload_lengths'][ordinal]:
                raise ValueError('Packet order or original length changed')
            value = randomize(payload, record['capture_id'], sample['id'], packet, seed)
            copied['payloads'][ordinal] = value
            cipher_ranges = [r for r in packet['ranges'] if r['kind'] == 'ciphertext']
            targeted = sum(r['end'] - r['start'] for r in cipher_ranges)
            if targeted != packet['byte_counts']['ciphertext']:
                raise ValueError('Transformation coverage differs from audited packet counts')
            changed = sum(a != b for a, b in zip(payload, value))
            audit.append(dict(capture=sample['capture'], capture_id=record['capture_id'], flow_id=sample['id'],
                label=sample['label'], split=record['split'], packet_index=packet['packet_index'],
                payload_ordinal=ordinal, frame=packet['frame'], protocol=record['protocol'],
                ciphertext_ranges=cipher_ranges, nearby_preserved_ranges=[r for r in packet['ranges'] if r['kind'] != 'ciphertext'],
                targeted_bytes=targeted, changed_bytes=changed,
                before_sha256=hashlib.sha256(bytes(payload)).hexdigest(), after_sha256=hashlib.sha256(bytes(value)).hexdigest()))
        if any(copied[k] != sample[k] for k in sample if k != 'payloads'):
            raise ValueError('STOP H/K: immutable sample metadata changed')
        result.append(copied)
    return result, audit


def main():
    decision = read(OUT / 'coverage_decision.json')
    if decision['status'] != 'PASS_FOR_NARROW_TLS12_GCM_ONLY':
        raise ValueError('Pre-transformation scientific gate not passed')
    if TRANSFORMED.exists():
        raise FileExistsError('Refusing to overwrite transformed data')
    samples, ranges = load_samples(), load_ranges()
    derived, audit = transformed_samples(samples, ranges)
    coverage = read(OUT / 'ciphertext_coverage.json')
    assert sum(p['targeted_bytes'] for p in audit) == coverage['global_counts']['ciphertext']
    # Explicitly test traversal independence against the entire actual dataset.
    reversed_derived, _ = transformed_samples(list(reversed(samples)), list(reversed(ranges)))
    assert derived == list(reversed(reversed_derived)), 'STOP J: traversal changes transformation'
    assert samples == load_samples(), 'Source cache was mutated'
    TRANSFORMED.mkdir(parents=True, exist_ok=False)
    path = TRANSFORMED / 'flows.json.gz'
    with path.open('xb') as output:
        with gzip.GzipFile(fileobj=output, filename='', mode='wb', mtime=0) as zipped:
            zipped.write(json.dumps(derived, sort_keys=True, separators=(',', ':')).encode())
    bounded, counts = [], {}
    for p in audit:
        if p['targeted_bytes'] and len(bounded) < 90:
            # Cover each capture rather than dumping complete actual payloads.
            if len([a for a in bounded if a['capture'] == p['capture']]) < 3:
                bounded.append(p)
        key = p['split'] + '/' + str(p['label'])
        counts.setdefault(key, dict(targeted_bytes=0, changed_bytes=0, affected_sample_ids=set()))
        counts[key]['targeted_bytes'] += p['targeted_bytes']
        counts[key]['changed_bytes'] += p['changed_bytes']
        if p['changed_bytes']:
            counts[key]['affected_sample_ids'].add(p['flow_id'])
    for row in counts.values():
        row['affected_samples'] = len(row.pop('affected_sample_ids'))
    identity = dict(version=VERSION, seed=SEED, range_manifest_sha256=coverage['range_manifest_sha256'],
        input_file=str(path), input_sha256=sha(path), graph_root=str(TRANSFORMED / 'graphs'),
        model_payload_mode='real', scientific_condition='tls12_gcm_randomized',
        stable_source_metadata='content_hash remains the source representation identity; input_sha256 identifies derived bytes',
        algorithm='SHA256(canonical sorted compact ASCII JSON identity); full 32-byte big-endian integer; NumPy default_rng/PCG64',
        identity_fields=['version', 'global_seed', 'source_capture_id', 'flow_id', 'packet_index_within_flow',
                         'ciphertext_range_index', 'range_start', 'range_end'],
        distribution='Independent uniform uint8 0..255; coincidental unchanged bytes permitted',
        targeted_bytes=sum(p['targeted_bytes'] for p in audit), changed_bytes=sum(p['changed_bytes'] for p in audit),
        samples=len(derived), samples_actually_changed=len({p['flow_id'] for p in audit if p['changed_bytes']}),
        split_class_counts=counts, split_sha256=decision['split_sha256'])
    save(OUT / 'transformation.json', identity)
    save(OUT / 'transformation_audit.json', dict(version=VERSION, packets=bounded,
        total_packet_records=len(audit), actual_payload_dumped=False))
    save(OUT / 'integrity_after_transformation.json', verify())
    print(json.dumps(identity, indent=2), flush=True)


if __name__ == '__main__':
    main()
