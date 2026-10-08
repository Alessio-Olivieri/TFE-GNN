"""Run one TLS/Real condition through the canonical, unchanged training routine."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from experiments.application_audit import read
from experiments.multiseed import independent_metrics
from experiments.capture_audit import sha, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--condition', choices=('real', 'tls12_gcm_randomized'), required=True)
    parser.add_argument('--training-seed', type=int, choices=(32, 42, 52), required=True)
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--prepared', type=Path, required=True, help='Output of experiments.tls_prepare')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--device', default='cuda:0')
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Use a fresh run output directory')
    validation = read(args.prepared / 'audit/validation.json')
    assert validation['passed'] and validation['exact_derived_inputs'] and validation['exact_range_manifest']
    recorded = read('results/tls_ciphertext_ablation/transformation.json')
    target = args.prepared / 'transformed_seed32'
    assert sha(target / 'flows.json.gz') == recorded['input_sha256']
    root = args.data if args.condition == 'real' else target
    subprocess.run([sys.executable, '-m', 'src.train', '--data', str(root),
        '--payload-mode', 'real', '--training-seed', str(args.training_seed),
        '--split-seed', '32', '--payload-seed', '32',
        '--split-manifest', 'results/splits-seed32.json', '--allow-shared-captures',
        '--epochs', '20', '--batch-size', '8', '--effective-batch-size', '32',
        '--results', str(args.output), '--result-name', 'model',
        '--checkpoints', str(args.output / 'checkpoints'), '--log-dir', str(args.output / 'logs'),
        '--device', args.device], check=True)
    result = read(args.output / 'model.json')
    if result['oom_attempts']:
        raise ValueError('OOM changed the matched configuration; no comparable TLS result will be recorded')
    assert result['batch_size'] == 8 and result['gradient_accumulation'] == 4
    accuracy, f1, matrix = independent_metrics(result['test_labels'], result['test_predictions'])
    assert abs(accuracy - result['accuracy']) < 1e-12 and abs(f1 - result['macro_f1']) < 1e-12
    assert matrix == result['confusion_matrix']
    references = read('results/tls_ciphertext_ablation/runs.json')['runs']
    reference = next(r for r in references if r['training_seed'] == args.training_seed and r['condition'] == args.condition)
    assert result['initial_state_sha256'] == reference['initial_state_sha256']
    if args.condition == 'real':
        assert result['test_predictions'] == reference['test_predictions'], 'Real baseline did not reproduce'
    result.update(condition=args.condition, model_payload_mode='real',
        ciphertext_randomization_seed=32, transformation_metadata=recorded,
        exact_input_validation=validation)
    save(args.output / 'run.json', result)


if __name__ == '__main__':
    main()
