"""Build fresh packet-local graphs and validate transformed actual inputs."""
import gzip
import hashlib
import json
from pathlib import Path

import torch

from recovery.application_audit import OUT, read
from recovery.application_integrity import verify
from recovery.application_transform import TRANSFORMED, transformed_samples, load_ranges
from recovery.capture_audit import load_samples, save, sha
from recovery.data import prepare_graphs, padded_graphs
from recovery.resources import ResourceMonitor
from recovery.run import read_split


def load_derived():
    metadata = read(OUT / 'transformation.json')
    if sha(metadata['input_file']) != metadata['input_sha256']:
        raise ValueError('Transformed input file changed')
    with gzip.open(metadata['input_file'], 'rt') as f:
        return json.load(f)


def main():
    if (OUT / 'transformation_validation.json').exists():
        raise FileExistsError('Refusing to overwrite transformation validation')
    samples, derived = load_samples(), load_derived()
    source_manifest = read_split(samples, Path('results/splits-seed32.json'), 32, 'flow')
    ranges = load_ranges()
    expected, packet_audit = transformed_samples(samples, ranges)
    if expected != derived:
        raise ValueError('STOP J/H: stored transformed bytes do not reproduce exactly')
    assert [s['id'] for s in derived] == [r['id'] for r in source_manifest['samples']]
    root = TRANSFORMED / 'graphs'
    if root.exists():
        raise FileExistsError('Fresh transformed graph root already exists; refusing any possible stale-cache reuse')
    monitor = ResourceMonitor().start()
    prepare_graphs(derived, root, 'real', 32, workers=4)
    checked, different = 0, 0
    by_id = {s['id']: s for s in derived}
    bounded = read(OUT / 'transformation_audit.json')['packets']
    for witness in bounded:
        sample = by_id[witness['flow_id']]
        actual = torch.load(root / 'real-32' / (sample['id'] + '.pt'), weights_only=False)[witness['payload_ordinal']]
        expected_graph = padded_graphs([sample['payloads'][witness['payload_ordinal']]], 150)[0]
        assert torch.equal(actual.x, expected_graph.x) and torch.equal(actual.edge_index, expected_graph.edge_index), 'STOP I: stale/incorrect payload graph'
        original = torch.load(Path('data/recovery/graphs/real-32') / (sample['id'] + '.pt'), weights_only=False)[witness['payload_ordinal']]
        different += not (torch.equal(actual.x, original.x) and torch.equal(actual.edge_index, original.edge_index))
        checked += 1
    assert checked and different
    caches = {}
    for name in ('headers', 'real-32'):
        rows = [[p.name, sha(p)] for p in sorted((root / name).glob('*.pt'))]
        assert len(rows) == 1674 and all(not p.is_symlink() for p in (root / name).glob('*.pt'))
        caches[name] = dict(files=len(rows), sha256=hashlib.sha256(json.dumps(rows).encode()).hexdigest())
    coverage = read(OUT / 'ciphertext_coverage.json')
    for row in coverage['rows']:
        if row['scope'] != 'split_class':
            continue
        split, label = row['id'].split('/')
        from recovery.audit import CLASSES
        selected = [p for p in packet_audit if p['split'] == split and p['label'] == CLASSES.index(label)]
        assert sum(p['targeted_bytes'] for p in selected) == row['ciphertext']
    resources = monitor.finish()
    integrity = verify(include_graphs=True)
    save(OUT / 'transformation_validation.json', dict(passed=True, source_integrity=integrity,
        exact_actual_transformation_reproduction=True, traversal_independence_all_samples=True,
        identical_sample_ids_labels_headers_packet_lengths_and_order=True,
        original_flow_split_reused=True, split_sha256=integrity['split_sha256'],
        all_non_ciphertext_bytes_unchanged=True, nonce_framing_plaintext_auth_unknown_preserved=True,
        complete_graph_reconstruction=True, cache_root=str(root), root_previously_absent=True,
        no_real_payload_graph_cache_reused=True, graph_caches=caches,
        graph_semantics_checks=checked, graph_semantics_changed=different,
        per_split_class_targeted_bytes_match_coverage=True,
        resources=resources, training_permitted=True,
        command="nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.application_prepare'"))
    print('Transformation and fresh-graph validation passed.', checked, 'actual graph witnesses;', different, 'changed.', flush=True)


if __name__ == '__main__':
    main()
