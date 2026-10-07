"""Compare every actual model input graph; never use comparison as training data."""
import collections
from pathlib import Path

import torch

from recovery.application_audit import OUT, read
from recovery.application_prepare import load_derived
from recovery.application_transform import TRANSFORMED, load_ranges
from recovery.capture_audit import save


def same(a, b):
    return torch.equal(a.x, b.x) and torch.equal(a.edge_index, b.edge_index)


def main():
    assert read(OUT / 'transformation_validation.json')['passed']
    samples, ranges = load_derived(), load_ranges()
    by_split_class = collections.defaultdict(lambda: collections.Counter())
    checked_headers = checked_payloads = changed_payloads = changed_samples = 0
    for sample, record in zip(samples, ranges):
        assert sample['id'] == record['id']
        for name in ('headers', 'real-32'):
            old = torch.load(Path('data/recovery/graphs') / name / (sample['id'] + '.pt'), weights_only=False)
            new = torch.load(TRANSFORMED / 'graphs' / name / (sample['id'] + '.pt'), weights_only=False)
            assert len(old) == len(new) == 50
            differences = [not same(a, b) for a, b in zip(old, new)]
            if name == 'headers':
                assert not any(differences), 'STOP H/I: unchanged header graphs differ'
                checked_headers += 50
            else:
                allowed = {p['payload_ordinal'] for p in record['packets'] if p['byte_counts']['ciphertext']}
                assert not any(changed and i not in allowed for i, changed in enumerate(differences)), 'Non-target packet graph changed'
                checked_payloads += 50
                changed_payloads += sum(differences)
                changed_samples += any(differences)
                key = record['split'] + '/' + str(record['label'])
                by_split_class[key]['samples'] += 1
                by_split_class[key]['graph_changed_samples'] += any(differences)
                by_split_class[key]['graph_changed_packets'] += sum(differences)
    assert changed_samples == 565, 'Model graph coverage differs from byte coverage'
    assert sum(r['graph_changed_samples'] for k, r in by_split_class.items() if k.startswith('test/')) == 85
    save(OUT / 'graph_pair_validation.json', dict(passed=True, all_header_graphs_identical=True,
        unchanged_packet_payload_graphs_identical=True, header_graphs_checked=checked_headers,
        payload_graphs_checked=checked_payloads, changed_payload_graphs=changed_payloads,
        changed_sample_graphs=changed_samples, split_class_counts=dict(by_split_class),
        original_graphs_used_only_for_validation_and_real_condition=True,
        transformed_condition_uses_only_fresh_transformed_graphs=True))
    print('All model graph pairs checked;', changed_samples, 'samples differ;', changed_payloads, 'packet graphs differ.', flush=True)


if __name__ == '__main__':
    main()
