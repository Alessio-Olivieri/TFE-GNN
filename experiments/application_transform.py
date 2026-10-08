"""Packet/range-specific TLS-GCM randomization, before ordinary graph creation."""
import copy
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np

from experiments.capture_audit import sha

VERSION = 'tls12-gcm-packet-range-pcg64-v1'
SEED = 32


def load_ranges(path, expected_sha256):
    if sha(path) != expected_sha256:
        raise ValueError('Ciphertext range manifest changed')
    with gzip.open(path, 'rt') as handle:
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


