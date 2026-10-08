"""Rebuild audited TLS inputs from source captures without training a model."""
import argparse
import collections
import csv
import gzip
import json
from pathlib import Path
import shutil

import torch

from experiments.application_audit import audit as tls_audit, read
from experiments.application_check import check
from experiments.application_transform import transformed_samples
from experiments.capture_audit import dissector, scan_capture, sha, save
from src.data import load_flows, prepare_graphs
from src.train import read_split


def validate_graph_pairs(samples, ranges, original, transformed):
    counts = collections.Counter()
    for sample, record in zip(samples, ranges):
        assert sample['id'] == record['id']
        for name in ('headers', 'real-32'):
            a = torch.load(original / name / (sample['id'] + '.pt'), weights_only=False)
            b = torch.load(transformed / name / (sample['id'] + '.pt'), weights_only=False)
            assert len(a) == len(b) == 50
            changed = [not (torch.equal(x.x, y.x) and torch.equal(x.edge_index, y.edge_index))
                       for x, y in zip(a, b)]
            if name == 'headers':
                assert not any(changed), 'Unchanged header graphs differ'
            else:
                allowed = {p['payload_ordinal'] for p in record['packets'] if p['byte_counts']['ciphertext']}
                assert not any(v and i not in allowed for i, v in enumerate(changed)), 'Untargeted graph changed'
                counts['changed_samples'] += any(changed)
                counts['changed_test_samples'] += any(changed) and record['split'] == 'test'
    assert counts['changed_samples'] == 565 and counts['changed_test_samples'] == 85
    return dict(counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', type=Path, required=True)
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--output', type=Path, required=True, help='Fresh directory for audit and derived inputs')
    parser.add_argument('--tshark', default=shutil.which('tshark'))
    parser.add_argument('--graph-workers', type=int, default=4)
    args = parser.parse_args()
    if not args.tshark:
        parser.error('TShark is required; use experiments/audit-shell.nix on NixOS')
    if args.output.exists():
        raise FileExistsError('Refusing to overwrite an audit or derived inputs')
    sources = read('results/capture_audit/source_sha256.json')
    for capture, expected in sources.items():
        assert sha(args.capture_root / capture) == expected, f'Source capture differs: {capture}'
    samples = load_flows(args.data)
    split_path = Path('results/splits-seed32.json')
    read_split(samples, split_path, 32, 'flow')
    args.output.mkdir(parents=True)
    audit_root = args.output / 'audit'
    audit_root.mkdir()
    with Path('results/capture_audit/capture_groups.csv').open() as f:
        groups = list(csv.DictReader(f))
    inventory = []
    for row in groups:
        capture = row['source_pcap']
        _, modeled, _ = scan_capture(args.capture_root / capture, capture, samples)
        inventory.append(dict(source_pcap=capture, source_sha256=sources[capture],
            capture_group_id=row['capture_group_id'],
            protocol_dissector=dissector(args.capture_root / capture, args.tshark, modeled)))
    inventory_path = audit_root / 'capture_inventory.json'
    save(inventory_path, dict(captures=inventory))
    save(audit_root / 'integrity_before.json', dict(capture_root=str(args.capture_root),
        capture_sha256_before=sources, split_manifest=str(split_path), split_sha256=sha(split_path)))
    tls_audit(audit_root, args.output / 'ranges', inventory_path)
    check(audit_root, args.tshark)
    coverage = read(audit_root / 'ciphertext_coverage.json')
    recorded = read('results/tls_ciphertext_ablation/transformation.json')
    assert coverage['range_manifest_sha256'] == recorded['range_manifest_sha256'], 'Audited range membership differs'
    assert (audit_root / 'ciphertext_coverage.csv').read_bytes() == Path('results/tls_ciphertext_ablation/ciphertext_coverage.csv').read_bytes()
    with gzip.open(coverage['range_manifest'], 'rt') as f:
        ranges = json.load(f)['samples']
    derived, packet_audit = transformed_samples(samples, ranges)
    reverse, _ = transformed_samples(list(reversed(samples)), list(reversed(ranges)))
    assert derived == list(reversed(reverse)), 'Traversal-dependent randomization'
    assert sum(p['targeted_bytes'] for p in packet_audit) == recorded['targeted_bytes']
    assert sum(p['changed_bytes'] for p in packet_audit) == recorded['changed_bytes']
    assert samples == load_flows(args.data), 'Source cache changed'
    target = args.output / 'transformed_seed32'
    target.mkdir()
    path = target / 'flows.json.gz'
    with path.open('xb') as f:
        with gzip.GzipFile(fileobj=f, filename='', mode='wb', mtime=0) as zipped:
            zipped.write(json.dumps(derived, sort_keys=True, separators=(',', ':')).encode())
    assert sha(path) == recorded['input_sha256'], 'Transformed inputs differ from validated experiment'
    shutil.copyfile(args.data / 'audit.json', target / 'audit.json')
    prepare_graphs(samples, args.data / 'graphs', 'real', 32, args.graph_workers)
    prepare_graphs(derived, target / 'graphs', 'real', 32, args.graph_workers)
    graph_counts = validate_graph_pairs(samples, ranges, args.data / 'graphs', target / 'graphs')
    for capture, expected in sources.items():
        assert sha(args.capture_root / capture) == expected, 'Source capture changed'
    save(audit_root / 'validation.json', dict(passed=True, source_captures_unchanged=True,
        exact_range_manifest=True, exact_derived_inputs=True, exact_coverage_csv=True,
        graph_counts=graph_counts, training=False))
    print('Validated TLS inputs:', target, flush=True)


if __name__ == '__main__':
    main()
