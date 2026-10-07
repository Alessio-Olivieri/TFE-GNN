"""Sequential fixed-split robustness experiment; preserve every pilot artifact."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys


ROOT = Path('results/multiseed')
NAMES = {'real': 'real', 'random': 'randomized', 'header-only': 'header_only'}
LABELS = {'real': 'Real payload', 'random': 'Randomized payload', 'header-only': 'Header-only'}
PAIRS = [('real', 'random'), ('random', 'header-only'), ('real', 'header-only')]


def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def save_json(path, value):
    with Path(path).open('x') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def save_csv(path, rows):
    with Path(path).open('x', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def independent_metrics(labels, predictions, classes=6):
    """Plain integer confusion-matrix arithmetic independent of sklearn."""
    if not labels or len(labels) != len(predictions):
        raise ValueError('Missing or misaligned saved predictions')
    matrix = [[0] * classes for _ in range(classes)]
    for y, p in zip(labels, predictions):
        matrix[y][p] += 1
    f1s = []
    for k in range(classes):
        tp = matrix[k][k]
        denominator = sum(matrix[k]) + sum(row[k] for row in matrix)
        f1s.append(2 * tp / denominator if denominator else 0.0)
    return sum(matrix[k][k] for k in range(classes)) / len(labels), statistics.mean(f1s), matrix


def stats(values):
    return statistics.mean(values), statistics.stdev(values)


def test_suite(root, phase):
    completed = subprocess.run([sys.executable, '-m', 'unittest',
                                'recovery.test_recovery', '-v'], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    path = root / f'tests-{phase}.txt'
    with path.open('x') as handle:
        handle.write(completed.stdout)
    print(completed.stdout, flush=True)
    completed.check_returncode()


def validate_and_summarize(root):
    experiment = json.loads((root / 'experiment.json').read_text())
    split_path = Path(experiment['split_manifest'])
    assert digest(split_path) == experiment['split_file_sha256'], 'Original split file changed'
    manifest = json.loads(split_path.read_text())
    indices = manifest['indices']
    records = manifest['samples']
    assert sorted(i for ix in indices.values() for i in ix) == list(range(len(records)))
    for split, ix in indices.items():
        assert ix == [i for i, r in enumerate(records) if r['split'] == split]
    for key in ('tuple_hash', 'content_hash', 'group_id'):
        locations = {}
        for record in records:
            locations.setdefault(record[key], set()).add(record['split'])
        assert all(len(v) == 1 for v in locations.values()), key
    group_counts = {s: len({records[i]['group_id'] for i in ix}) for s, ix in indices.items()}
    test_ids = [records[i]['id'] for i in indices['test']]
    test_labels = [records[i]['label'] for i in indices['test']]
    reference = json.loads(Path('results/baseline.json').read_text())
    runs, checks, pilot_reproduction = [], [], {}
    for seed in experiment['training_seeds']:
        for mode, filename in NAMES.items():
            path = root / f'seed_{seed}' / f'{filename}.json'
            result = json.loads(path.read_text())
            assert result['training_seed'] == seed and result['split_seed'] == 32
            assert result['payload_seed'] == 32 and result['condition'] == mode
            assert result['epochs_completed'] == 20
            assert [h['epoch'] for h in result['history']] == list(range(1, 21))
            assert result['hyperparameters'] == reference['hyperparameters']
            for key in ('batch_size', 'gradient_accumulation', 'effective_batch_size'):
                assert result[key] == reference[key], (path, key)
            assert not result['oom_attempts'], 'OOM changed the controlled setup'
            assert result['split_manifest'] == experiment['split_manifest']
            assert result['split_file_sha256'] == experiment['split_file_sha256']
            assert result['split_manifest_sha256'] == manifest['sample_manifest_sha256']
            assert result['split_sizes'] == manifest['sizes']
            assert result['split_counts'] == manifest['counts']
            assert result['split_group_counts'] == group_counts
            assert result['test_sample_ids'] == test_ids
            assert result['test_labels'] == test_labels
            assert result['best_epoch'] == max(result['history'], key=lambda h:
                (h['validation_macro_f1'], -h['validation_loss']))['epoch']
            assert not result['tracked_git_status'], 'Tracked source changed during training'
            accuracy, f1, matrix = independent_metrics(result['test_labels'], result['test_predictions'])
            assert abs(accuracy - result['accuracy']) < 1e-12
            assert abs(f1 - result['macro_f1']) < 1e-12
            assert matrix == result['confusion_matrix']
            checks.append(dict(path=str(path), training_seed=seed, condition=mode,
                               epochs=20, accuracy_recomputed=accuracy, macro_f1_recomputed=f1,
                               split_file_sha256=result['split_file_sha256']))
            if seed == 32:
                old_name = {'real': 'baseline', 'random': 'random-seed32',
                            'header-only': 'header-only-seed32'}[mode]
                old = json.loads(Path(f'results/{old_name}.json').read_text())
                pilot_reproduction[mode] = dict(predictions_identical=old['test_predictions'] == result['test_predictions'],
                    accuracy_difference=result['accuracy'] - old['accuracy'],
                    macro_f1_difference=result['macro_f1'] - old['macro_f1'])
            runs.append(result)
    assert len(runs) == 9
    assert len({r['git_commit'] for r in runs}) == 1
    assert all(r['source_sha256'] == runs[0]['source_sha256'] for r in runs)
    for seed in experiment['training_seeds']:
        assert len({r['initial_state_sha256'] for r in runs if r['training_seed'] == seed}) == 1
    assert len({r['initial_state_sha256'] for r in runs}) == 3
    captures_after = {p: digest(Path(experiment['capture_root']) / p)
                      for p in experiment['capture_sha256_before']}
    assert captures_after == experiment['capture_sha256_before'], 'Capture bytes changed'
    for p, expected in experiment['preserved_files_sha256'].items():
        assert digest(p) == expected, f'Existing artifact changed: {p}'
    assert digest(experiment['existing_archive']) == experiment['existing_archive_sha256']
    backup_commit = subprocess.check_output(['git', 'rev-parse', experiment['existing_backup_branch']], text=True).strip()
    assert backup_commit == experiment['existing_backup_commit']
    for name, expected in experiment['graph_cache_sha256_before'].items():
        rows = [[p.name, digest(p)] for p in sorted((Path('data/recovery/graphs') / name).glob('*.pt'))]
        assert len(rows) == len(records)
        assert hashlib.sha256(json.dumps(rows).encode()).hexdigest() == expected, name
    validation = dict(passed=True, runs=checks, identical_split_membership_all_nine=True,
        grouped_split_counts=group_counts, group_leakage_keys_checked=['tuple_hash', 'content_hash', 'group_id'],
        independent_metric_method='Integer confusion-matrix arithmetic, tolerance 1e-12',
        same_initialization_within_seed=True, distinct_initialization_across_seeds=True,
        all_nine_completed_twenty_epochs=True, no_oom=True,
        capture_hashes_verified=len(captures_after), capture_sha256_after=captures_after,
        preserved_existing_files=len(experiment['preserved_files_sha256']),
        original_backup_and_archive_preserved=True, original_graph_caches_preserved=True,
        preliminary_seed32_reproduction=pilot_reproduction,
        source_commit=runs[0]['git_commit'], tests_before='tests-before.txt', tests_after='tests-after.txt')
    save_json(root / 'validation.json', validation)
    rows = []
    for r in runs:
        rows.append(dict(condition=r['condition'], training_seed=r['training_seed'], split_seed=r['split_seed'],
            payload_seed=r['payload_seed'], accuracy=r['accuracy'], macro_precision=r['macro_precision'],
            macro_recall=r['macro_recall'], macro_f1=r['macro_f1'], test_loss=r['test_loss'],
            epochs=r['epochs_completed'], best_epoch=r['best_epoch'],
            train_size=r['split_sizes']['train'], validation_size=r['split_sizes']['validation'],
            test_size=r['split_sizes']['test'], train_groups=group_counts['train'],
            validation_groups=group_counts['validation'], test_groups=group_counts['test']))
    save_csv(root / 'all_runs.csv', rows)
    summaries = []
    for mode in NAMES:
        selected = [r for r in runs if r['condition'] == mode]
        acc_mean, acc_std = stats([r['accuracy'] for r in selected])
        f1_mean, f1_std = stats([r['macro_f1'] for r in selected])
        summaries.append(dict(condition=mode, n=3, accuracy_mean=acc_mean, accuracy_std=acc_std,
                              macro_f1_mean=f1_mean, macro_f1_std=f1_std, std_ddof=1))
    save_csv(root / 'summary.csv', summaries)
    by_key = {(r['training_seed'], r['condition']): r for r in runs}
    differences, paired = [], []
    for a, b in PAIRS:
        selected = []
        for seed in experiment['training_seeds']:
            ra, rb = by_key[seed, a], by_key[seed, b]
            row = dict(comparison=f'{a} - {b}', training_seed=seed,
                       accuracy_difference=ra['accuracy'] - rb['accuracy'],
                       macro_f1_difference=ra['macro_f1'] - rb['macro_f1'])
            differences.append(row)
            selected.append(row)
        am, ast = stats([r['accuracy_difference'] for r in selected])
        fm, fst = stats([r['macro_f1_difference'] for r in selected])
        paired.append(dict(comparison=f'{a} - {b}', n=3, accuracy_difference_mean=am,
                           accuracy_difference_std=ast, macro_f1_difference_mean=fm,
                           macro_f1_difference_std=fst, std_ddof=1))
    save_csv(root / 'paired_differences.csv', differences)
    save_csv(root / 'paired_summary.csv', paired)
    lines = ['# PRELIMINARY fixed-split multi-seed ISCX-VPN experiment', '',
        'Objective: measure training variability while comparing captured payload, randomized payload, and header-only TFE-GNN.', '',
        'Training/model seeds: **32, 42, 52**. Split seed: **32**. Payload-transformation seed: **32**, fixed across training seeds.',
        'All nine runs were newly trained for 20 epochs, sequentially; best checkpoint selected by validation macro F1 (ties: validation loss). Test evaluation occurred after training.', '',
        '## Fixed-split methodology', '',
        'Reused the pilot manifest `results/splits-seed32.json` without regeneration. '
        f'File SHA256: `{experiment["split_file_sha256"]}`. '
        f'Sample/group assignment fingerprint: `{manifest["sample_manifest_sha256"]}`.',
        'Canonical bidirectional TCP endpoint tuples and identical representations are grouped transitively across captures. '
        'Identical sample IDs, group membership, ordered indices, labels, and split fingerprints were checked across all nine runs.',
        '**This is flow-disjoint, not capture-disjoint.** Some samples in train, validation and test originate from the same captures '
        f'({len(manifest["captures_present_in_all_three_splits"])} captures appear in all three). Capture-level leakage remains possible.', '',
        '## Dataset and preprocessing', '',
        'ISCX-VPN2016: the same 31 local original captures in `../ICSX-VPN`, six folder labels. '
        'IPv4/TCP only; bidirectional endpoint-tuple flows per capture, no idle timeout or reassembly, retransmissions retained. '
        'Exclude empty-payload flows and flows with >10,000 nonempty data packets. '
        'First 50 TCP headers (including ACK-only packets) and independently first 50 nonempty payloads; '
        'remove IP addresses/TCP ports, truncate to 40/150 bytes, pad with token 256, PMI window 5.', '',
        '| Class | Total | Train | Validation | Test |', '|---|---:|---:|---:|---:|']
    for label in manifest['classes']:
        counts = [manifest['counts'][s][label] for s in ('train', 'validation', 'test')]
        lines.append(f'| {label} | {sum(counts)} | {counts[0]} | {counts[1]} | {counts[2]} |')
    lines += [f'| **Total samples** | **{len(records)}** | **{manifest["sizes"]["train"]}** | '
              f'**{manifest["sizes"]["validation"]}** | **{manifest["sizes"]["test"]}** |',
        f'| **Distinct groups** | **{manifest["groups"]}** | **{group_counts["train"]}** | '
        f'**{group_counts["validation"]}** | **{group_counts["test"]}** |', '',
        'Randomization uses the unchanged pilot procedure: SHA256 of `32:{sample_id}:{packet_ordinal}:payload`, '
        'first 16 bytes interpreted big endian as NumPy default_rng/PCG64 seed; uniformly random uint8 bytes of the '
        'full original packet payload length, before truncation, padding and graph construction. '
        'Reuses the pilot `random-32` graphs. Headers, labels, lengths, packet order and splits remain unchanged. '
        'Fixing this transformation isolates training variability; payload-randomization variability is not measured. '
        'Header-only bypasses the payload encoder and supplies a constant zero vector to fusion; it removes payload length information from that branch too.', '',
        '## Training configuration', '',
        'Same recovered original TFE-GNN PyG model, not CLE-TFE. Embedding 64, four GraphSAGE layers of width 128, '
        'cross-gated fusion, two-layer bidirectional LSTM hidden width 1024. Adam LR 0.01, 10% warmup then cosine '
        'to 0.0001, dropout 0.2, no weight decay/label smoothing, FP32. Minibatch 8, accumulation 4 (effective 32); '
        'BatchNorm sees 8 samples, as in the pilot. No test-set tuning.',
        'Seed Python, NumPy, Torch CPU/CUDA and DataLoader generators by training seed. Worker Python/NumPy RNGs '
        'use `torch.initial_seed() % 2**32`; Torch seeds workers automatically. `PYTHONHASHSEED=32` is held fixed. '
        'Deterministic Torch algorithms, deterministic cuDNN, no benchmarking/TF32; CUBLAS_WORKSPACE_CONFIG=:4096:8. '
        'Graph caches remain on CPU/disk and only current minibatches transfer to CUDA.', '',
        f'Source commit used by all runs: `{runs[0]["git_commit"]}`. Exact commands, software/GPU versions, '
        'configuration, RNG metadata, predictions, class metrics and epoch histories are in every individual JSON.', '',
        '## Per-seed held-out results', '', '| Training seed | Condition | Accuracy | Macro F1 | Test loss | Best epoch |',
        '|---:|---|---:|---:|---:|---:|']
    for r in runs:
        lines.append(f'| {r["training_seed"]} | {LABELS[r["condition"]]} | {100*r["accuracy"]:.2f}% | '
                     f'{r["macro_f1"]:.4f} | {r["test_loss"]:.4f} | {r["best_epoch"]} |')
    lines += ['', '## Mean ± sample standard deviation', '',
        'Sample standard deviation uses **ddof=1** across three training seeds. Accuracy is percent; '
        'paired accuracy differences are percentage points. Macro F1 and its differences use the 0–1 scale.', '',
        '| Condition | Accuracy mean ± std | Macro F1 mean ± std |', '|---|---:|---:|']
    for r in summaries:
        lines.append(f'| {LABELS[r["condition"]]} | {100*r["accuracy_mean"]:.2f}% ± {100*r["accuracy_std"]:.2f}% | '
                     f'{r["macro_f1_mean"]:.4f} ± {r["macro_f1_std"]:.4f} |')
    lines += ['', '## Paired differences', '', '| Comparison | Seed | Accuracy difference (pp) | Macro F1 difference |',
              '|---|---:|---:|---:|']
    for r in differences:
        lines.append(f'| {r["comparison"]} | {r["training_seed"]} | {100*r["accuracy_difference"]:+.2f} | '
                     f'{r["macro_f1_difference"]:+.4f} |')
    lines += ['', '| Comparison | Accuracy difference mean ± std (pp) | Macro F1 difference mean ± std |',
              '|---|---:|---:|']
    for r in paired:
        lines.append(f'| {r["comparison"]} | {100*r["accuracy_difference_mean"]:+.2f} ± '
                     f'{100*r["accuracy_difference_std"]:.2f} | {r["macro_f1_difference_mean"]:+.4f} ± '
                     f'{r["macro_f1_difference_std"]:.4f} |')
    lines += ['', '## Validation and resources', '',
        '- All nine runs completed 20 epochs with the unchanged pilot hyperparameters and no OOM retries.',
        '- All nine share the exact pilot split file and sample/group membership. No tuple/content/group overlap across partitions.',
        '- Accuracy, macro F1 and confusion matrices independently recomputed from all nine saved prediction/label arrays (tolerance 1e-12).',
        '- Matching initial model states within each training seed; three distinct initial states across seeds. Common committed source hashes.',
        '- Existing recovery tests plus new seed/split/aggregation checks passed before and after execution; see `tests-before.txt` and `tests-after.txt`.',
        '- All 31 original capture SHA256 hashes match both the pilot audit and the pre-experiment snapshot. '
        f'All {len(experiment["preserved_files_sha256"])} existing non-recovery tracked artifacts remain byte-identical, including preliminary results/reports.',
        f'- Seed-32 reproduction versus pilot: `{json.dumps(pilot_reproduction, sort_keys=True)}`.', '',
        '| Seed | Condition | Peak device VRAM (GiB) | Peak CUDA reserved (GiB) | Peak process-tree RSS (GiB) | Peak host used (GiB) |',
        '|---:|---|---:|---:|---:|---:|']
    for r in runs:
        resource = r['resources']
        lines.append(f'| {r["training_seed"]} | {LABELS[r["condition"]]} | '
            f'{resource["peak_gpu_device_used_mib"]/1024:.2f} | {resource["peak_gpu_reserved_mib"]/1024:.2f} | '
            f'{resource["peak_process_tree_rss_mib"]/1024:.2f} | {resource["peak_host_used_mib"]/1024:.2f} |')
    lines += ['', 'VRAM sampled every 2 seconds and RAM every 0.5 seconds; CUDA allocator peaks are exact. '
        'Sampling can miss brief spikes, summed RSS can double-count shared pages, and host/device totals include other processes.', '',
        '## Interpretation and limitations', '',
        f'Across these three fixed-split training seeds, the mean real-minus-random accuracy difference is '
        f'{100*paired[0]["accuracy_difference_mean"]:+.2f} percentage points and the mean macro-F1 difference is '
        f'{paired[0]["macro_f1_difference_mean"]:+.4f}. '
        'This compares retained payload byte content with length-preserving randomized bytes on this pilot.',
        'Assess the observed effect using the tables above; these are preliminary fixed-split training-seed results, '
        'not final six-class scientific conclusions. Retained transport payload may include plaintext, protocol framing, '
        'handshakes and incidental/background traffic. This comparison does **not** isolate encrypted ciphertext itself.',
        'Three training seeds characterize initialization/training variability on one selected split and one fixed randomization; '
        'they are not independent datasets, confidence intervals, or evidence of capture-disjoint generalization. '
        'Capture-folder labels may include background flows, and excluding very long flows can remove primary application traffic. '
        'The pilot was already observed; this is not a new untouched test set. PyG recovery and minibatch-8 BatchNorm '
        'are documented differences from upstream and this is not an exact published-result reproduction.',
        'Before stronger conclusions: obtain enough independent captures for capture-disjoint partitions, validate per-flow labels '
        'and encryption boundaries, isolate ciphertext versus framing/plaintext, repeat across grouped splits and randomization seeds, '
        'and quantify uncertainty with appropriate independent source groups. Do not tune on this test set.', '',
        '## Artifacts and reproduction', '',
        'Run from the repository root: `nix-shell recovery/shell.nix --run '
        "'.venv-recovery/bin/python -m recovery.multiseed'`. Existing complete runs are validated and reused on restart; "
        'existing outputs are never overwritten. Use a new output root and matching experiment snapshot for a separate study.',
        'Individual results: `results/multiseed/seed_{32,42,52}/{real,randomized,header_only}.json` '
        '(and `.txt`); each includes labels/predictions and class metrics. Checkpoints: '
        '`checkpoints/multiseed/seed_{32,42,52}/`; logs: `logs/multiseed/seed_{32,42,52}/`.',
        'Aggregate files: `all_runs.csv`, `summary.csv`, `paired_differences.csv`, `paired_summary.csv`, '
        '`summary.md`, `validation.json`, `experiment.json`, `tests-before.txt`, `tests-after.txt` under '
        '`results/multiseed/`. Original recovery/preliminary reports, baseline results, backup branch and archive are preserved.', '']
    report = '\n'.join(lines)
    for path in (root / 'summary.md', Path('RESULTS_MULTI_SEED.md')):
        with path.open('x') as handle:
            handle.write(report)
    print('\n'.join(lines[lines.index('## Mean ± sample standard deviation'):lines.index('## Validation and resources')]), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--summarize-only', action='store_true')
    args = parser.parse_args()
    root = args.root
    experiment = json.loads((root / 'experiment.json').read_text())
    assert digest(experiment['split_manifest']) == experiment['split_file_sha256']
    if args.summarize_only:
        validate_and_summarize(root)
        return
    if not (root / 'tests-before.txt').exists():
        test_suite(root, 'before')
    for seed in experiment['training_seeds']:
        for mode, filename in NAMES.items():
            output = root / f'seed_{seed}'
            result_path = output / f'{filename}.json'
            if result_path.exists():
                existing = json.loads(result_path.read_text())
                assert existing['training_seed'] == seed and existing['split_seed'] == 32
                assert existing['payload_seed'] == 32 and existing['epochs_completed'] == 20
                assert existing['split_file_sha256'] == experiment['split_file_sha256']
                print('REUSING completed multi-seed run:', result_path, flush=True)
                continue
            command = [sys.executable, '-m', 'recovery.run', '--payload-mode', mode,
                '--training-seed', str(seed), '--split-seed', '32', '--payload-seed', '32',
                '--split-manifest', experiment['split_manifest'], '--epochs', '20',
                '--batch-size', '8', '--effective-batch-size', '32', '--allow-shared-captures',
                '--results', str(output), '--result-name', filename,
                '--checkpoints', f'checkpoints/multiseed/seed_{seed}',
                '--log-dir', f'logs/multiseed/seed_{seed}']
            print('STARTING', seed, mode, flush=True)
            subprocess.run(command, check=True)
    if not (root / 'tests-after.txt').exists():
        test_suite(root, 'after')
    validate_and_summarize(root)


if __name__ == '__main__':
    main()
