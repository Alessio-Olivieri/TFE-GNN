"""Validate published metrics, paired contrasts, coverage and artifact hashes."""
import csv
import hashlib
import json
from pathlib import Path
import statistics

from experiments.multiseed import independent_metrics

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return json.loads((ROOT / path).read_text())


def rows(path):
    with (ROOT / path).open() as f:
        return list(csv.DictReader(f))


def verify():
    provenance = read('results/provenance.json')
    for artifact in provenance['artifacts']:
        path = ROOT / artifact['path']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact['sha256'], str(path)
    manifest = read('results/splits-seed32.json')
    split_sha = hashlib.sha256((ROOT / 'results/splits-seed32.json').read_bytes()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps(manifest['samples'], sort_keys=True).encode()).hexdigest()
    assert fingerprint == manifest['sample_manifest_sha256']
    indices = manifest['indices']
    assert sorted(i for ix in indices.values() for i in ix) == list(range(len(manifest['samples'])))
    for split, ix in indices.items():
        assert ix == [i for i, r in enumerate(manifest['samples']) if r['split'] == split]
    for key in ('tuple_hash', 'content_hash', 'group_id'):
        membership = {}
        for r in manifest['samples']:
            assert membership.setdefault(r[key], r['split']) == r['split']
    ids = [manifest['samples'][i]['id'] for i in indices['test']]
    labels = [manifest['samples'][i]['label'] for i in indices['test']]
    total = 0
    families = {}
    for name, count in [('payload_ablation', 9), ('tls_ciphertext_ablation', 6)]:
        prefix = 'results/' + name + '/'
        runs = read(prefix + 'runs.json')['runs']
        families[name] = runs
        assert len(runs) == count
        for r in runs:
            assert r['training_seed'] in (32, 42, 52)
            assert r['split_seed'] == r['payload_seed'] == 32
            assert r['split_file_sha256'] == split_sha
            assert r['test_sample_ids'] == ids and r['test_labels'] == labels
            assert [h['epoch'] for h in r['history']] == list(range(1, 21))
            assert r['best_epoch'] == max(r['history'], key=lambda h: (h['validation_macro_f1'], -h['validation_loss']))['epoch']
            assert not r['capture_disjoint'] and not r['oom_attempts']
            accuracy, f1, matrix = independent_metrics(labels, r['test_predictions'])
            assert abs(accuracy - r['accuracy']) < 1e-12 and abs(f1 - r['macro_f1']) < 1e-12
            assert matrix == r['confusion_matrix']
            total += 1
        for seed in (32, 42, 52):
            assert len({r['initial_state_sha256'] for r in runs if r['training_seed'] == seed}) == 1
        for summary in rows(prefix + 'summary.csv'):
            selected = [r for r in runs if r['condition'] == summary['condition']]
            assert len(selected) == int(summary['n']) == 3 and summary['std_ddof'] == '1'
            for field in ('accuracy', 'macro_f1'):
                assert abs(statistics.mean(r[field] for r in selected) - float(summary[field + '_mean'])) < 1e-12
                assert abs(statistics.stdev(r[field] for r in selected) - float(summary[field + '_std'])) < 1e-12
        by_key = {(r['training_seed'], r['condition']): r for r in runs}
        for row in rows(prefix + 'all_runs.csv'):
            r = by_key[int(row['training_seed']), row['condition']]
            for field in ('accuracy', 'macro_f1', 'macro_precision', 'macro_recall', 'test_loss'):
                assert abs(float(row[field]) - r[field]) < 1e-12
        differences = rows(prefix + 'paired_differences.csv')
        for row in differences:
            a, b = row['comparison'].split(' - ')
            if name == 'tls_ciphertext_ablation':
                a, b = 'real', 'tls12_gcm_randomized'
            ra, rb = by_key[int(row['training_seed']), a], by_key[int(row['training_seed']), b]
            for field in ('accuracy', 'macro_f1'):
                assert abs(ra[field] - rb[field] - float(row[field + '_difference'])) < 1e-12
        for summary in rows(prefix + 'paired_summary.csv'):
            chosen = [r for r in differences if r['comparison'] == summary['comparison']]
            for field in ('accuracy', 'macro_f1'):
                values = [float(r[field + '_difference']) for r in chosen]
                assert abs(statistics.mean(values) - float(summary[field + '_difference_mean'])) < 1e-12
                assert abs(statistics.stdev(values) - float(summary[field + '_difference_std'])) < 1e-12
    for r in families['tls_ciphertext_ablation']:
        if r['condition'] == 'real':
            old = next(x for x in families['payload_ablation'] if x['condition'] == 'real' and x['training_seed'] == r['training_seed'])
            assert r['test_predictions'] == old['test_predictions']
            assert r['initial_state_sha256'] == old['initial_state_sha256']
    coverage = rows('results/tls_ciphertext_ablation/ciphertext_coverage.csv')
    for row in coverage:
        assert sum(int(row[k]) for k in ('ciphertext', 'framing', 'plaintext', 'authentication', 'padding', 'unknown', 'unsupported')) == int(row['payload_bytes'])
    global_row = next(r for r in coverage if r['scope'] == 'global')
    assert int(global_row['ciphertext']) == 838456 and int(global_row['samples_with_ciphertext']) == 565
    heldout = next(r for r in coverage if r['scope'] == 'split' and r['id'] == 'test')
    assert int(heldout['samples_with_ciphertext']) == 85 and int(heldout['samples']) == 250
    feasibility = read('results/capture_audit/feasibility.json')
    assert feasibility['protocol'] == 'STOP' and not feasibility['training_permitted']
    groups = rows('results/capture_audit/capture_groups.csv')
    for c, expected in feasibility['group_counts'].items():
        assert len({r['capture_group_id'] for r in groups if json.loads(r['sample_counts']).get(c, 0)}) == expected
    return dict(runs=total, saved_predictions=total * len(labels), artifact_hashes='passed', metrics='passed', capture_independence='STOP')


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
