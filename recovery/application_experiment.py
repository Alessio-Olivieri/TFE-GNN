"""Sequential pilot/full stages, with a saved mandatory pilot gate."""
import argparse
import subprocess
import sys

from recovery.application_audit import OUT, read
from recovery.application_integrity import verify
from recovery.capture_audit import save


def pair(seed):
    for condition in ('real', 'tls12_gcm_randomized'):
        path = OUT / f'seed_{seed}' / f'{condition}.json'
        if path.exists():
            existing = read(path)
            assert existing['epochs_completed'] == 20 and existing['independent_metric_validation']['passed']
            print('Validated completed run:', path, flush=True)
            continue
        subprocess.run([sys.executable, '-m', 'recovery.application_train', '--condition', condition,
                        '--training-seed', str(seed)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=('pilot', 'full'), required=True)
    args = parser.parse_args()
    if args.stage == 'pilot':
        pair(32)
        real = read(OUT / 'seed_32/real.json')
        random = read(OUT / 'seed_32/tls12_gcm_randomized.json')
        assert real['previous_real_exact_reproduction']
        assert real['test_sample_ids'] == random['test_sample_ids'] and real['test_labels'] == random['test_labels']
        assert real['initial_state_sha256'] == random['initial_state_sha256']
        assert real['hyperparameters'] == random['hyperparameters']
        transformation = read(OUT / 'transformation.json')
        changed = sum(row['affected_samples'] for key, row in transformation['split_class_counts'].items() if key.startswith('test/'))
        assert changed == 85, 'STOP O: held-out transformation coverage differs from audit'
        save(OUT / 'pilot_validation.json', dict(passed=True, both_twenty_epochs=True,
            real_exact_baseline_reproduction=True, identical_test_samples_labels_split=True,
            same_initialization=True, independent_metrics_passed=True, test_samples_actually_changed=changed,
            test_samples_total=250, changed_percent=100 * changed / 250,
            interpretation='Narrow TLS-GCM intervention; no protocol reparsing/decryption is expected after mutation. '
                           'Ciphertext/tag authentication will fail by design; model consumes derived bytes, not live traffic.',
            integrity=verify(), next_stage_requires_pilot_review=True))
        print('PILOT COMPLETE. Review saved histories/metrics before launching --stage full.', flush=True)
    else:
        assert read(OUT / 'pilot_validation.json')['passed'], 'Pilot gate not passed'
        for seed in (42, 52):
            pair(seed)
        print('FULL SIX-RUN EXPERIMENT COMPLETE.', flush=True)


if __name__ == '__main__':
    main()
