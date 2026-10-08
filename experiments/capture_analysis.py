"""Reproduce conservative acquisition grouping without fitting a model."""
import argparse
import json
from pathlib import Path

from experiments.capture_audit import (acquisition_key, refine_capture_groups,
    assess_feasibility, scan_capture, sha, save, csv_save)
from experiments.capture_audit_report import group_evidence
from src.capture import CLASSES
from src.data import load_flows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', type=Path, required=True)
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Use a fresh audit output directory')
    samples = load_flows(args.data)
    sources = json.loads(Path('results/capture_audit/source_sha256.json').read_text())
    inventory = []
    for capture, expected in sources.items():
        assert sha(args.capture_root / capture) == expected, f'Source capture differs: {capture}'
        scan, _, _ = scan_capture(args.capture_root / capture, capture, samples)
        label = capture.split('/')[0]
        count = sum(s['capture'] == capture for s in samples)
        inventory.append(dict(source_pcap=capture, capture_group_id=acquisition_key(capture),
            labels=[label], usable_samples=count, sample_counts={c: count if c == label else 0 for c in CLASSES},
            first_timestamp=scan['first'], last_timestamp=scan['last'],
            group_reason='Conservative related-activity grouping; independence unverified'))
    refined, links = refine_capture_groups(inventory, samples)
    decision = assess_feasibility(refined)
    assert decision == json.loads(Path('results/capture_audit/feasibility.json').read_text())
    args.output.mkdir(parents=True)
    csv_save(args.output / 'capture_groups.csv', refined)
    save(args.output / 'feasibility.json', decision)
    save(args.output / 'group_evidence.json', dict(groups=group_evidence(refined), links=links))
    for capture, expected in sources.items():
        assert sha(args.capture_root / capture) == expected
    print(decision['protocol'] + ': ' + decision['reason'])


if __name__ == '__main__':
    main()
