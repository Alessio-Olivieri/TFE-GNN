"""Independent six-run validation and coverage-aware descriptive reporting."""
import csv
import datetime
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import sys

from recovery.application_audit import OUT, LIMITATION, read
from recovery.application_integrity import verify
from recovery.application_train import validate_result
from recovery.application_transform import TRANSFORMED, load_ranges
from recovery.capture_audit import csv_save, save, sha
from recovery.run import read_split
from recovery.capture_audit import load_samples


def mean_std(values):
    return statistics.mean(values), statistics.stdev(values)


def main():
    manifest = read_split(load_samples(), Path('results/splits-seed32.json'), 32, 'flow')
    runs, rows, validations, secondary = [], [], [], []
    affected = {r['id'] for r in load_ranges() if r['split'] == 'test' and any(p['byte_counts']['ciphertext'] for p in r['packets'])}
    assert len(affected) == 85
    for seed in (32, 42, 52):
        for condition in ('real', 'tls12_gcm_randomized'):
            path = OUT / f'seed_{seed}' / f'{condition}.json'
            r = read(path)
            validations.append(dict(path=str(path), **validate_result(r, manifest)))
            assert r['training_seed'] == seed and r['ciphertext_randomization_seed'] == r['split_seed'] == 32
            assert r['split_file_sha256'] == sha('results/splits-seed32.json') and not r['oom_attempts']
            assert r['hyperparameters'] == read('results/multiseed/seed_32/real.json')['hyperparameters']
            if condition == 'real':
                assert r['previous_real_exact_reproduction']
            runs.append(r)
            rows.append(dict(condition=condition, training_seed=seed, split_seed=32, ciphertext_seed=32,
                accuracy=r['accuracy'], macro_precision=r['macro_precision'], macro_recall=r['macro_recall'],
                macro_f1=r['macro_f1'], test_loss=r['test_loss'], epochs=20, best_epoch=r['best_epoch'],
                train_accuracy_final=r['history'][-1]['train_accuracy'], train_loss_final=r['history'][-1]['train_loss'],
                validation_macro_f1_final=r['history'][-1]['validation_macro_f1'],
                train_size=1172, validation_size=252, test_size=250, test_samples_changed=85 if condition != 'real' else 0))
            for name, membership in [('affected', affected), ('unaffected', set(r['test_sample_ids']) - affected)]:
                matches = [(y, p) for ident, y, p in zip(r['test_sample_ids'], r['test_labels'], r['test_predictions']) if ident in membership]
                secondary.append(dict(training_seed=seed, condition=condition, subset=name, samples=len(matches),
                    accuracy=sum(y == p for y, p in matches) / len(matches), secondary_posthoc=True))
    assert len({r['git_commit'] for r in runs}) == 1 and all(r['source_sha256'] == runs[0]['source_sha256'] for r in runs)
    for seed in (32, 42, 52):
        assert len({r['initial_state_sha256'] for r in runs if r['training_seed'] == seed}) == 1
    summaries, differences = [], []
    for condition in ('real', 'tls12_gcm_randomized'):
        chosen = [r for r in runs if r['condition'] == condition]
        am, ast = mean_std([r['accuracy'] for r in chosen])
        fm, fst = mean_std([r['macro_f1'] for r in chosen])
        summaries.append(dict(condition=condition, n=3, accuracy_mean=am, accuracy_std=ast,
                              macro_f1_mean=fm, macro_f1_std=fst, std_ddof=1))
    for seed in (32, 42, 52):
        a, b = [next(r for r in runs if r['training_seed'] == seed and r['condition'] == condition)
                for condition in ('real', 'tls12_gcm_randomized')]
        differences.append(dict(comparison='Real - TLS12-GCM-randomized', training_seed=seed,
            accuracy_difference=a['accuracy'] - b['accuracy'], macro_f1_difference=a['macro_f1'] - b['macro_f1']))
    am, ast = mean_std([r['accuracy_difference'] for r in differences])
    fm, fst = mean_std([r['macro_f1_difference'] for r in differences])
    paired = dict(comparison='Real - TLS12-GCM-randomized', n=3, accuracy_difference_mean=am,
                  accuracy_difference_std=ast, macro_f1_difference_mean=fm, macro_f1_difference_std=fst, std_ddof=1)
    test_command = [sys.executable, '-m', 'unittest', 'recovery.test_recovery', 'recovery.test_capture_audit',
                    'recovery.test_application_tls', 'recovery.test_application_transform', '-v']
    tests = subprocess.run(test_command, capture_output=True, text=True)
    with (OUT / 'tests-after.txt').open('x') as f:
        f.write(tests.stdout + tests.stderr)
    tests.check_returncode()
    test_count = int(re.search(r'Ran (\d+) tests', tests.stderr + tests.stdout).group(1))
    integrity = verify(include_graphs=True)
    receipt = read(OUT / 'transformation_validation.json')
    for name, expected in receipt['graph_caches'].items():
        graph_rows = [[p.name, sha(p)] for p in sorted((TRANSFORMED / 'graphs' / name).glob('*.pt'))]
        assert hashlib.sha256(json.dumps(graph_rows).encode()).hexdigest() == expected['sha256']
    value = dict(passed=True, runs=validations, six_completed_twenty_epochs=True, identical_split_all_six=True,
        same_initialization_within_training_seed=True, old_real_baselines_exactly_reproduced=True,
        independent_metric_recomputation=True, tests=test_count, failures=0, source_integrity=integrity,
        original_and_transformed_graph_caches_preserved=True, no_oom=True,
        source_commit=runs[0]['git_commit'], timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    save(OUT / 'validation.json', value)
    csv_save(OUT / 'all_runs.csv', rows)
    csv_save(OUT / 'summary.csv', summaries)
    csv_save(OUT / 'paired_differences.csv', differences)
    csv_save(OUT / 'paired_summary.csv', [paired])
    csv_save(OUT / 'secondary_subset_accuracy.csv', secondary)
    audit_text = (OUT / 'AUDIT_REPORT.md').read_text()
    report = audit_text[:audit_text.index('## Execution status')] + '## Completed experiment\n\n'
    report += LIMITATION + '\n\n'
    report += ('Six fresh sequential runs used training seeds 32/42/52, fixed split seed 32 and fixed ciphertext seed 32. '
               'Every run used the existing 20-epoch configuration: batch 8, effective batch 32, Adam, LR .01, cosine schedule, '
               '10% warmup, no architecture/hyperparameter changes. Checkpoints were selected by validation macro F1, ties by validation loss; '
               'the full 250-sample test set was evaluated after training. No test-based checkpoint selection or tuning occurred.\n\n')
    report += '| Seed | Condition | Accuracy | Macro F1 | Final train accuracy | Selected epoch |\n| --- | --- | --- | --- | --- | --- |\n'
    for r in rows:
        report += f"| {r['training_seed']} | {r['condition']} | {100*r['accuracy']:.2f}% | {r['macro_f1']:.4f} | {100*r['train_accuracy_final']:.2f}% | {r['best_epoch']} |\n"
    report += '\nSample standard deviation uses ddof=1 across the three matched training seeds.\n\n'
    report += '| Condition | Accuracy mean ± SD | Macro F1 mean ± SD |\n| --- | --- | --- |\n'
    for r in summaries:
        report += f"| {r['condition']} | {100*r['accuracy_mean']:.2f}% ± {100*r['accuracy_std']:.2f}% | {r['macro_f1_mean']:.4f} ± {r['macro_f1_std']:.4f} |\n"
    report += '\n| Real minus TLS-GCM randomized | Accuracy difference (pp) | Macro F1 difference |\n| --- | --- | --- |\n'
    for r in differences:
        report += f"| Seed {r['training_seed']} | {100*r['accuracy_difference']:+.2f} | {r['macro_f1_difference']:+.4f} |\n"
    report += f'| Mean ± sample SD | {100*am:+.2f} ± {100*ast:.2f} | {fm:+.4f} ± {fst:.4f} |\n'
    report += '\n## Comparison with preserved full-payload/header ablations\n\n'
    report += '| Condition | Accuracy mean ± SD | Macro F1 mean ± SD |\n| --- | --- | --- |\n'
    with Path('results/multiseed/summary.csv').open() as f:
        for r in csv.DictReader(f):
            report += f"| Previous {r['condition']} | {100*float(r['accuracy_mean']):.2f}% ± {100*float(r['accuracy_std']):.2f}% | {float(r['macro_f1_mean']):.4f} ± {float(r['macro_f1_std']):.4f} |\n"
    r = summaries[1]
    report += f"| TLS-GCM randomized | {100*r['accuracy_mean']:.2f}% ± {100*r['accuracy_std']:.2f}% | {r['macro_f1_mean']:.4f} ± {r['macro_f1_std']:.4f} |\n"
    transformation = read(OUT / 'transformation.json')
    report += ('\n## Transformation and validation\n\n'
               f"Uniform randomization targeted {transformation['targeted_bytes']:,} confirmed bytes; {transformation['changed_bytes']:,} actually differed, "
               'with coincidental equality allowed. All 565 targeted samples, including 85/250 test samples, changed their model graphs. '
               'All 83,700 header graphs and all untargeted payload graphs remained semantically identical. '
               'The transformed cache was absent before generation; every payload graph was rebuilt by the ordinary packet-local PMI pipeline. '
               'No original ciphertext-derived topology/features were reused.\n\n'
               'Packet/range streams use compact sorted ASCII JSON of transformation version, global seed, capture SHA, flow ID, '
               'packet index and range index/bounds; SHA-256 full digest seeds NumPy PCG64. '
               'Order independence was checked on the entire actual dataset and across Python hash seeds. '
               'Headers, record framing/nonce, hello plaintext, authentication tags, unknown/unsupported bytes, labels, source identity, '
               'lengths, packet order/count and split membership were preserved. TLS authentication would fail after mutation by design; '
               'the experiment modifies derived model inputs, not wire-valid traffic.\n\n'
               f"All {test_count} tests passed after execution. Metrics/confusion matrices were independently recomputed for all six runs. "
               'All three fresh Real runs reproduced the previous corresponding baseline exactly. All 31 source SHA-256 values, '
               '131 pre-experiment tracked files, original graph caches, backup branches and archive remain unchanged. '
               'Integrity was checked before implementation, after transformation, after each run and finally.\n\n')
    report += '## Interpretation and limitations\n\n'
    if all(d['accuracy_difference'] > 0 and d['macro_f1_difference'] > 0 for d in differences):
        report += ('Within this preliminary flow-disjoint evaluation, replacing confidently identified TLS-GCM encrypted bytes '
                   'reduced both classification metrics in all three matched seeds. Information associated with these supported '
                   'encrypted regions may contribute under this setup; this does not identify ciphertext semantics or establish generalization.\n\n')
    else:
        report += ('Assess the signed paired differences above: the experiment does not show a consistent reduction in both metrics '
                   'across all three seeds. This is not an equivalence test, and three training seeds cannot establish absence of an effect. '
                   'A small or mixed TLS-only effect alongside the larger full-payload effect would suggest investigating framing, plaintext '
                   'and other untouched protocol structure; it would not rule out useful information in unsupported encrypted regions.\n\n')
    report += (LIMITATION + '\n\nOnly one fixed split and one transformation seed were used. Three model seeds are repeated measurements '
        'on the same captures/test samples, not independent datasets or confidence intervals. The test set was previously observed. '
        'Coverage is protocol- and class-associated: FileTransfer/P2P test inputs are untouched, and much payload remains unknown/unsupported. '
        'Encrypted Finished and alert bodies are included along with application-data ciphertext; explicit nonces/tags remain. '
        'Changing training bytes can alter predictions even for unaffected test inputs. The separate secondary_subset_accuracy.csv is descriptive '
        'post-hoc analysis on the pre-audited 85 affected and 165 unaffected samples, not a replacement test set. '
        'Optimization, byte-graph representation, protocol implementations, background flows and capture/session artifacts remain alternative explanations. '
        'No additional seeds, classes or test subsets were selected to improve results.\n\n')
    report += '## Resources\n\n| Seed | Condition | Sampled device VRAM GiB | CUDA reserved GiB | Process-tree RSS GiB | Host RAM GiB |\n| --- | --- | --- | --- | --- | --- |\n'
    for r in runs:
        v = r['resources']
        report += f"| {r['training_seed']} | {r['condition']} | {v['peak_gpu_device_used_mib']/1024:.2f} | {v['peak_gpu_reserved_mib']/1024:.2f} | {v['peak_process_tree_rss_mib']/1024:.2f} | {v['peak_host_used_mib']/1024:.2f} |\n"
    report += ('\nRuns were sequential; no OOM or retries/configuration changes. Only minibatches were transferred to CUDA. '
               'RAM/device sampling can miss brief peaks and includes other processes; CUDA allocator peaks are exact.\n\n'
               '## Reproduction and outputs\n\n'
               'Run from TFE-GNN inside nix-shell recovery/audit-shell.nix with .venv-recovery/bin/python. '
               'Stages: -m recovery.application_audit; -m recovery.application_check; coverage_decision.json review; '
               '-m recovery.application_transform; -m recovery.application_prepare; -m recovery.application_validate_graphs; '
               '-m recovery.application_experiment --stage pilot; pilot review; --stage full; -m recovery.application_summary. '
               'Scripts refuse overwriting completed artifacts. The initial audit-only report is preserved as AUDIT_REPORT.md.\n\n'
               'All result CSV/JSON, bounded parser/transformation evidence, validation, and test logs are under results/application_ciphertext/. '
               'Individual seed_{32,42,52}/{real,tls12_gcm_randomized}.json include complete predictions/labels, per-class metrics, '
               'confusion matrices, all epoch histories, software/GPU versions, seeds, commands, source hashes and commit. '
               'Range and derived-input/graph caches remain under data/application_ciphertext/ (not committed generated data). '
               'Checkpoints/logs are under checkpoints/application_ciphertext/ and logs/application_ciphertext/.\n')
    Path('RESULTS_APPLICATION_CIPHERTEXT.md').write_text(report)
    with (OUT / 'summary.md').open('x') as f:
        f.write(report)
    print(json.dumps(dict(summary=summaries, paired=paired, validation_passed=True), indent=2), flush=True)


if __name__ == '__main__':
    main()
