"""Audit exact retained TLS ciphertext coverage before any transformation."""
import collections
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import subprocess

from recovery.application_tls import VERSION, KINDS, classify_flow
from recovery.audit import CLASSES, SETTINGS
from recovery.capture_audit import csv_save, load_samples, save, scan_capture, sha
from recovery.resources import ResourceMonitor

OUT = Path('results/application_ciphertext')
DATA = Path('data/application_ciphertext')
LIMITATION = ('These results use the existing flow-disjoint evaluation. The available captures '
             'cannot support defensible six-class capture-independent evaluation, so capture-level '
             'generalization remains unresolved.')


def read(path):
    return json.loads(Path(path).read_text())


def aggregate(records, scope, key):
    counts = collections.Counter()
    captures = set()
    for r in records:
        counts['samples'] += 1
        counts['samples_with_payload'] += bool(r['packets'])
        any_cipher = False
        captures.add(r['capture'])
        for p in r['packets']:
            counts['payload_packets'] += 1
            counts['payload_bytes'] += p['retained_payload_bytes']
            counts.update(p['byte_counts'])
            counts['packets_with_ciphertext'] += p['byte_counts']['ciphertext'] > 0
            any_cipher |= p['byte_counts']['ciphertext'] > 0
        counts['samples_with_ciphertext'] += any_cipher
    result = dict(scope=scope, id=key, captures=len(captures), **counts)
    for kind in KINDS:
        result[kind] = counts[kind]
    assert sum(counts[k] for k in KINDS) == counts['payload_bytes']
    result['ciphertext_byte_percent'] = 100 * counts['ciphertext'] / counts['payload_bytes'] if counts['payload_bytes'] else 0
    result['affected_sample_percent'] = 100 * counts['samples_with_ciphertext'] / counts['samples'] if counts['samples'] else 0
    return result


def main():
    if (OUT / 'ciphertext_coverage.json').exists():
        raise FileExistsError('Refusing to overwrite a completed coverage audit')
    before = read(OUT / 'integrity_before.json')
    from recovery.run import read_split
    samples = load_samples()
    split = read_split(samples, Path(before['split_manifest']), 32, 'flow')
    assert sha(before['split_manifest']) == before['split_sha256']
    split_by_id = {s['id']: s['split'] for s in split['samples']}
    inventory = read('results/capture_disjoint/capture_inventory_effective.json')['captures']
    manifest, bounded, suite_checks, disagreements = [], [], [], []
    reasons = collections.Counter()
    monitor = ResourceMonitor().start()
    for capture in inventory:
        rel = capture['source_pcap']
        assert sha(Path(before['capture_root']) / rel) == before['capture_sha256_before'][rel]
        _, _, flows = scan_capture(Path(before['capture_root']) / rel, rel, samples)
        hellos = collections.defaultdict(list)
        for hello in capture['protocol_dissector']['server_hellos']:
            hellos[hello['sample_id']].append(hello)
        seen_bounded = 0
        for flow in flows:
            sample = flow['sample']
            classified = classify_flow(flow)
            if classified['protocol'] == 'TLS1.2_AES_GCM':
                expected = (classified['negotiated_version'], classified['negotiated_suite'])
                observed = []
                for hello in hellos[sample['id']]:
                    versions = [int(v, 0) for v in hello['version'].split(',') if v]
                    suites = [int(v, 0) for v in hello['cipher_suite'].split(',') if v]
                    observed.extend((v, s) for v in versions for s in suites)
                if expected not in observed:
                    disagreements.append(dict(sample_id=sample['id'], capture=rel,
                                               parser=list(expected), tshark=[list(p) for p in observed]))
                    # Do not retain any purported ciphertext on failed corroboration.
                    classified['protocol'] = 'UNKNOWN'
                    classified['reason'] = 'independent_server_hello_not_corroborated'
                    classified['records'] = []
                    for p in classified['packets']:
                        p['protocol'], p['ranges'] = 'UNKNOWN', []
                        p['byte_counts'] = {k: p['retained_payload_bytes'] if k == 'unknown' else 0 for k in KINDS}
                else:
                    suite_checks.append(dict(sample_id=sample['id'], capture=rel, version=expected[0],
                                             suite=expected[1], passed=True))
            reasons[classified['reason']] += 1
            row = dict(id=sample['id'], capture=rel, capture_id=capture['source_sha256'], label=sample['label'],
                capture_group_id=capture['capture_group_id'], split=split_by_id[sample['id']],
                protocol=classified['protocol'], reason=classified['reason'],
                packets=classified['packets'], records=classified['records'])
            manifest.append(row)
            for p, original in zip(row['packets'], flow['selected']):
                if p['byte_counts']['ciphertext'] and seen_bounded < 3:
                    bounded.append(dict(capture=rel, capture_id=row['capture_id'], flow_id=sample['id'],
                        label=sample['label'], split=row['split'], packet_index=p['packet_index'], frame=p['frame'],
                        protocol=row['protocol'], payload_ordinal=p['payload_ordinal'],
                        retained_payload_sha256=hashlib.sha256(original['payload'][:150]).hexdigest(),
                        payload_length=p['payload_length'], retained_payload_bytes=p['retained_payload_bytes'],
                        classified_ranges=p['ranges'], byte_counts=p['byte_counts'],
                        record_evidence=classified['records'][:6], transformed=False))
                    seen_bounded += 1
        print(rel, 'eligible=', len(flows), 'confirmed TLS-GCM flows=',
              sum(r['capture'] == rel and any(p['byte_counts']['ciphertext'] for p in r['packets']) for r in manifest), flush=True)
    ordered = {r['id']: r for r in manifest}
    assert len(manifest) == len(ordered) == len(samples) == 1674
    manifest = [ordered[s['id']] for s in samples]
    rows = [aggregate(manifest, 'global', 'ALL')]
    for label in CLASSES:
        rows.append(aggregate([r for r in manifest if CLASSES[r['label']] == label], 'class', label))
    for protocol in sorted({r['protocol'] for r in manifest}):
        rows.append(aggregate([r for r in manifest if r['protocol'] == protocol], 'protocol', protocol))
    for name in ('train', 'validation', 'test'):
        rows.append(aggregate([r for r in manifest if r['split'] == name], 'split', name))
        for label in CLASSES:
            rows.append(aggregate([r for r in manifest if r['split'] == name and CLASSES[r['label']] == label],
                                  'split_class', name + '/' + label))
    for capture in inventory:
        rows.append(aggregate([r for r in manifest if r['capture'] == capture['source_pcap']], 'capture', capture['source_pcap']))
    for group in sorted({r['capture_group_id'] for r in manifest}):
        rows.append(aggregate([r for r in manifest if r['capture_group_id'] == group], 'capture_group', group))
    assert rows[0]['payload_packets'] == 40962 and rows[0]['payload_bytes'] == 4666377
    DATA.mkdir(exist_ok=False, parents=True)
    range_path = DATA / 'ranges.json.gz'
    # Sorted stable JSON; deterministic gzip timestamp/header, no raw payloads.
    with range_path.open('xb') as output:
        with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
            zipped.write(json.dumps(dict(version=VERSION, samples=manifest), sort_keys=True,
                                    separators=(',', ':')).encode())
    resources = monitor.finish()
    coverage = dict(version=VERSION, evaluation='existing flow-disjoint', limitation=LIMITATION,
        split_manifest=before['split_manifest'], split_sha256=before['split_sha256'],
        range_manifest=str(range_path), range_manifest_sha256=sha(range_path),
        independent_server_hello_checks=len(suite_checks), independent_disagreements=disagreements,
        rejection_reasons=dict(reasons), rows=rows, global_counts=rows[0], resources=resources,
        preprocessing=SETTINGS, padding_token_excluded_from_byte_counts=True,
        protocol_scope='Only structurally verified TLS1.2 AES-GCM with exact mapping. '
                       'Includes encrypted Finished, application-data and alert bodies; explicit nonce/tag preserved. '
                       'TLS CBC/other versions, SSH encrypted packets and unclassified traffic are not targeted.',
        category_semantics=dict(unknown='Unclassified bytes, incomplete records, unsupported setup fields or missing stream/state',
                                unsupported='Recognized unsupported protected TLS bodies or SSH bytes after its identification banner',
                                plaintext='Fully parsed clear TLS hello messages and verified HTTP headers or SSH banners',
                                padding='Identified padding only; zero does not assert absence in unsupported bytes'),
        sources=['https://www.rfc-editor.org/rfc/rfc5246', 'https://www.rfc-editor.org/rfc/rfc5288',
                 'https://www.rfc-editor.org/rfc/rfc5289', 'https://www.rfc-editor.org/rfc/rfc4253'],
        source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        source_sha256={str(p): sha(p) for p in sorted(Path('recovery').glob('application_*.py'))},
        command="nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.application_audit'",
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), randomization_implemented=False)
    save(OUT / 'ciphertext_coverage.json', coverage)
    csv_save(OUT / 'ciphertext_coverage.csv', rows)
    save(OUT / 'parser_evidence.json', dict(version=VERSION, samples=bounded, suite_checks=suite_checks,
        disagreements=disagreements, evidence_only=True, payload_dumped=False))
    assert all(sha(Path(before['capture_root']) / rel) == value for rel, value in before['capture_sha256_before'].items())
    print(json.dumps([r for r in rows if r['scope'] in ('global', 'class', 'split', 'protocol')], indent=2), flush=True)


if __name__ == '__main__':
    main()
