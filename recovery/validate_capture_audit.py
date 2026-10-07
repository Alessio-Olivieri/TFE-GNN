"""Fail loudly if the read-only capture audit altered data or overstates results."""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from recovery.capture_audit import (OUT, acquisition_key, assess_feasibility, load_samples,
                                    save, sha, validate_assignment, refine_capture_groups)
from recovery.multiseed import NAMES, independent_metrics
from recovery.resources import ResourceMonitor


def read(path):
    return json.loads(Path(path).read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def previous_metrics():
    """Read the old nine runs; never call their result-writing orchestration."""
    experiment = read('results/multiseed/experiment.json')
    split_path = Path(experiment['split_manifest'])
    require(sha(split_path) == experiment['split_file_sha256'], 'Previous fixed split changed')
    split = read(split_path)
    test_ids = [split['samples'][i]['id'] for i in split['indices']['test']]
    labels = [split['samples'][i]['label'] for i in split['indices']['test']]
    reference = read('results/baseline.json')
    checks = []
    for seed in (32, 42, 52):
        for mode, name in NAMES.items():
            path = Path('results/multiseed') / f'seed_{seed}' / f'{name}.json'
            run = read(path)
            require(run['test_labels'] == labels and run['test_sample_ids'] == test_ids,
                    f'{path}: held-out membership differs')
            require(run['split_file_sha256'] == sha(split_path), f'{path}: split fingerprint differs')
            require(run['training_seed'] == seed and run['split_seed'] == run['payload_seed'] == 32,
                    f'{path}: seed metadata differs')
            require(run['epochs_completed'] == 20 and [h['epoch'] for h in run['history']] == list(range(1, 21)),
                    f'{path}: incomplete original run')
            require(run['hyperparameters'] == reference['hyperparameters'], f'{path}: hyperparameters differ')
            accuracy, f1, matrix = independent_metrics(labels, run['test_predictions'])
            require(abs(accuracy - run['accuracy']) < 1e-12 and abs(f1 - run['macro_f1']) < 1e-12,
                    f'{path}: metric mismatch')
            require(matrix == run['confusion_matrix'], f'{path}: confusion matrix mismatch')
            checks.append(dict(path=str(path), training_seed=seed, condition=mode,
                               accuracy=accuracy, macro_f1=f1, confusion_matrix=matrix, epochs=20))
    return dict(runs=checks, runs_checked=len(checks), method='Integer confusion-matrix arithmetic independent of sklearn',
                tolerance=1e-12, identical_old_test_membership=True,
                old_split_sha256=sha(split_path), new_predictions_created=False)


def main():
    if (OUT / 'validation.json').exists():
        raise FileExistsError('Refusing to overwrite completed audit validation')
    monitor = ResourceMonitor().start()
    before = read(OUT / 'integrity_before.json')
    initial_inventory = read(OUT / 'capture_inventory.json')
    inventory = read(OUT / 'capture_inventory_effective.json')
    records = read(OUT / 'provenance_manifest_effective.json')
    samples = load_samples()
    feasibility = read(OUT / 'effective_feasibility.json')
    refined, links = refine_capture_groups(initial_inventory['captures'], samples)
    reverse, reverse_links = refine_capture_groups(list(reversed(initial_inventory['captures'])), list(reversed(samples)))
    require(refined == inventory['captures'], 'Effective capture inventory is not reproducible')
    require({c['source_pcap']: c['capture_group_id'] for c in refined} ==
            {c['source_pcap']: c['capture_group_id'] for c in reverse} and links == reverse_links,
            'Order-dependent session grouping')
    require(feasibility == assess_feasibility(inventory['captures']), 'Stored feasibility decision differs')
    require(feasibility['protocol'] == 'STOP' and not feasibility['training_permitted'], 'Scientific STOP was bypassed')
    require(feasibility == assess_feasibility(list(reversed(inventory['captures']))), 'Order-dependent feasibility')
    require(not records['split_constructed'] and not records['fold_constructed'], 'Unexpected evaluation assignments')
    require(not (OUT / 'split_manifest.json').exists() and not (OUT / 'fold_manifest.json').exists(),
            'An invalid capture evaluation manifest was created')
    validate_assignment(records['samples'], {r['id']: r['capture_group_id'] for r in records['samples']}, samples)
    sources = {c['source_pcap']: c for c in inventory['captures']}
    require(len(sources) == len(inventory['captures']) == 31, 'Capture inventory is incomplete or duplicated')
    by_capture = collections.Counter(s['capture'] for s in samples)
    for r in records['samples']:
        require(r['capture_group_id'] == sources[r['capture']]['capture_group_id'], 'Provenance group differs from authoritative grouping')
        sample = next(s for s in samples if s['id'] == r['id'])
        for key in ('tuple_hash', 'content_hash'):
            require(sample[key] == r[key], f'Source {key} changed')
    for name, c in sources.items():
        require(c['usable_samples'] == by_capture[name], f'{name}: sample count mismatch')
        require(c['initial_activity_group_id'] == acquisition_key(name), f'{name}: initial group mismatch')
        require(c['stage_counts']['usable_samples'] == c['usable_samples'], 'Trace count mismatch')
    for key in ('tuple_hash', 'content_hash'):
        locations = collections.defaultdict(set)
        for r in records['samples']:
            locations[r[key]].add(r['capture_group_id'])
        require(all(len(groups) == 1 for groups in locations.values()), f'{key}: linked sources separated')
    capture_after = {name: sha(Path(before['capture_root']) / name) for name in sources}
    require(capture_after == before['capture_sha256_before'], 'Original PCAP bytes changed')
    require(capture_after == {e['path']: e['sha256'] for e in read('data/recovery/audit.json')['captures']},
            'PCAP differs from original recovery hash')
    for path, expected in before['preserved_files_sha256'].items():
        require(sha(path) == expected, f'Preserved tracked artifact changed: {path}')
    caches = {}
    for name, expected in before['graph_cache_sha256_before'].items():
        rows = [[p.name, sha(p)] for p in sorted((Path('data/recovery/graphs') / name).glob('*.pt'))]
        require(len(rows) == len(samples), f'{name}: graph count changed')
        fingerprint = hashlib.sha256(json.dumps(rows).encode()).hexdigest()
        require(fingerprint == expected, f'{name}: graph cache changed')
        caches[name] = dict(files=len(rows), sha256=fingerprint)
    require(sha(before['archive']) == before['archive_sha256'], 'Original archive changed')
    for branch, expected in before['backup_branches'].items():
        actual = subprocess.check_output(['git', 'rev-parse', branch], text=True).strip()
        require(actual == expected, f'Backup branch changed: {branch}')
    scope = read('results/ciphertext_randomized/transport_scope_audit.json')
    require(len(scope['captures']) == 31, 'Outer transport inventory incomplete')
    for row in scope['captures']:
        require(row['raw_packets'] == sources[row['source_capture']]['stage_counts']['raw_packets'], 'Raw packet count mismatch')
        require(row['raw_packets'] == sum(row[k] for k in
                ('raw_outer_tcp_packets', 'raw_outer_udp_packets', 'raw_outer_other_packets')), 'Outer L4 counts inconsistent')
    observations = scope['openvpn_label_observations']
    require(len(observations) == 6 and all(r['inside_icmp_quote'] and not r['survives_model_filter'] for r in observations),
            'OpenVPN observations require renewed scientific review')
    coverage = read('results/ciphertext_randomized/ciphertext_coverage.json')
    require(not coverage['range_parser_executed'] and not coverage['randomization_executed'] and
            not coverage['representation_rebuilt'], 'Ciphertext phase ran despite missing evaluation protocol')
    require(coverage['total_model_payload_bytes'] == sum(c['stage_counts']['model_real_payload_bytes'] for c in sources.values()),
            'Coverage denominator mismatch')
    for row in coverage['by_scope']:
        require(row['confirmed_ciphertext_bytes'] is None and row['unknown_bytes'] is None,
                'Unassessed coverage was converted into a measured count')
    old = previous_metrics()
    command = [sys.executable, '-m', 'unittest', 'recovery.test_recovery', 'recovery.test_capture_audit', '-v']
    tests = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with (OUT / 'tests-after.txt').open('x') as handle:
        handle.write(tests.stdout)
    print(tests.stdout, flush=True)
    tests.check_returncode()
    # Check the immutable source again after tests as well as after the scan.
    require({name: sha(Path(before['capture_root']) / name) for name in sources} == capture_after,
            'Original captures changed during tests')
    resources = monitor.finish()
    value = dict(passed=True, timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        code_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        command="nix-shell recovery/audit-shell.nix --run '.venv-recovery/bin/python -m recovery.validate_capture_audit'",
        source_sample_records=len(records['samples']), sample_mapping_complete=True, labels_unchanged=True,
        groups_consistent=True, feasibility_deterministic=True, raw_to_cached_byte_trace_verified_by_capture_audit=True,
        candidate_acquisition_groups=len({r['capture_group_id'] for r in records['samples']}),
        verified_independent_group_count=None, protocol='STOP', new_training_runs=0,
        capture_split_leakage_check='NOT APPLICABLE: no valid split/folds created',
        capture_hashes_verified=len(capture_after), capture_sha256_after=capture_after,
        existing_tracked_files_preserved=len(before['preserved_files_sha256']),
        original_graph_caches_preserved=caches, backups_and_archive_preserved=True,
        earlier_metric_recomputation=old, tests_command=command, tests_returncode=tests.returncode,
        tests_output='tests-after.txt', tests_before_modifications='15 existing tests passed (Phase 0)',
        ciphertext_mutation_checks='NOT RUN: no transformation implemented after scientific STOP',
        no_new_gpu_training=True, no_oom=True, resources=resources)
    save(OUT / 'validation.json', value)
    print(json.dumps({k: value[k] for k in ('passed', 'protocol', 'source_sample_records',
        'capture_hashes_verified', 'existing_tracked_files_preserved', 'new_training_runs')}, indent=2), flush=True)


if __name__ == '__main__':
    main()
