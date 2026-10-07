"""One unchanged-model flow-disjoint TLS-GCM ablation run; OOM means STOP.

Reuses recovery.run.train_attempt directly. Scientific input condition is
separate from the internal model/cache mode 'real'; architecture is unchanged.
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import torch

from recovery.application_audit import OUT, LIMITATION, read
from recovery.application_integrity import verify
from recovery.application_prepare import load_derived
from recovery.application_transform import TRANSFORMED
from recovery.capture_audit import load_samples, save, sha
from recovery.multiseed import independent_metrics
from recovery.run import read_split, software, train_attempt


def validate_result(result, manifest):
    labels = [manifest['samples'][i]['label'] for i in manifest['indices']['test']]
    ids = [manifest['samples'][i]['id'] for i in manifest['indices']['test']]
    if result['test_labels'] != labels or result['test_sample_ids'] != ids:
        raise ValueError('STOP K/N: predictions are misaligned with original held-out samples')
    accuracy, f1, matrix = independent_metrics(labels, result['test_predictions'])
    if abs(accuracy - result['accuracy']) > 1e-12 or abs(f1 - result['macro_f1']) > 1e-12 or matrix != result['confusion_matrix']:
        raise ValueError('STOP N: independently recomputed metrics differ')
    if [h['epoch'] for h in result['history']] != list(range(1, 21)):
        raise ValueError('Incomplete 20-epoch run')
    return dict(passed=True, accuracy=accuracy, macro_f1=f1, confusion_matrix=matrix,
                method='Independent integer confusion-matrix arithmetic', tolerance=1e-12)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--condition', choices=('real', 'tls12_gcm_randomized'), required=True)
    parser.add_argument('--training-seed', type=int, choices=(32, 42, 52), required=True)
    cli = parser.parse_args()
    validation = read(OUT / 'transformation_validation.json')
    if not validation['passed'] or not validation['training_permitted']:
        raise ValueError('Transformation gate not passed')
    if not read(OUT / 'graph_pair_validation.json')['passed']:
        raise ValueError('Complete actual-model graph validation not passed')
    seed, condition = cli.training_seed, cli.condition
    output_dir = OUT / f'seed_{seed}'
    output_dir.mkdir(exist_ok=True)
    output = output_dir / f'{condition}.json'
    if output.exists():
        raise FileExistsError(f'Refusing to overwrite run {output}')
    integrity_before = verify()
    originals = load_samples()
    manifest = read_split(originals, Path('results/splits-seed32.json'), 32, 'flow')
    samples = originals if condition == 'real' else load_derived()
    for a, b in zip(originals, samples):
        if any(a[k] != b[k] for k in a if k != 'payloads'):
            raise ValueError('STOP K: immutable source identities differ')
    assert len(samples) == len(originals) == 1674
    data_root = Path('data/recovery') if condition == 'real' else TRANSFORMED
    args = argparse.Namespace(seed=seed, payload_seed=32, payload_mode='real',
        data=data_root, epochs=20, effective_batch_size=32, workers=1, device='cuda:0',
        checkpoints=Path('checkpoints/application_ciphertext') / f'seed_{seed}' / condition)
    args.checkpoints.mkdir(parents=True, exist_ok=True)
    log_dir = Path('logs/application_ciphertext') / f'seed_{seed}'
    log_dir.mkdir(parents=True, exist_ok=True)
    if not torch.cuda.is_available():
        raise RuntimeError('CUDA unavailable; no CPU/configuration fallback')
    with (log_dir / f'{condition}.log').open('x', buffering=1) as log_file:
        def log(message):
            print(message, flush=True)
            print(message, file=log_file, flush=True)
        versions = software()
        log(json.dumps(dict(condition=condition, training_seed=seed, split_seed=32,
                            ciphertext_seed=32, software=versions, split_sizes=manifest['sizes'])))
        try:
            trained = train_attempt(samples, manifest, args, 8, log)
        except torch.cuda.OutOfMemoryError as error:
            save(output_dir / f'{condition}-STOP_OOM.json', dict(status='STOP_OOM', condition=condition,
                training_seed=seed, batch_size=8, configuration_changed=False, message=str(error)))
            raise  # Explicitly no retry, no batch-size or architecture change.
    reference = read(Path('results/multiseed') / f'seed_{seed}' / 'real.json')
    result = {**copy.deepcopy(reference), **trained}
    metadata = read(OUT / 'transformation.json')
    result.update(condition=condition, model_payload_mode='real', seed=seed, training_seed=seed,
        split_seed=32, payload_seed=32, ciphertext_randomization_seed=32, epochs_completed=len(trained['history']),
        effective_seeds=dict(python=seed, numpy=seed, torch_cpu=seed, torch_cuda=seed,
            dataloader_generator=seed, dataloader_workers='torch.initial_seed() modulo 2**32',
            pythonhashseed=os.environ.get('PYTHONHASHSEED'), split=32, ciphertext_randomization=32),
        payload_randomization=dict(applied=False, reason='No full-payload randomization; see ciphertext_randomization'),
        ciphertext_randomization=dict(applied=condition != 'real', seed=32, version=metadata['version'],
            algorithm=metadata['algorithm'], identity_fields=metadata['identity_fields'],
            distribution=metadata['distribution'], range_manifest_sha256=metadata['range_manifest_sha256'],
            transformed_input_sha256=metadata['input_sha256'] if condition != 'real' else None),
        graph_cache=str(data_root / 'graphs/real-32'),
        graph_reconstruction_validation='results/application_ciphertext/transformation_validation.json',
        coverage_metadata='results/application_ciphertext/ciphertext_coverage.json',
        transformation_metadata='results/application_ciphertext/transformation.json',
        preliminary=True, capture_disjoint=False, limitation=LIMITATION,
        split_sizes=manifest['sizes'], split_counts=manifest['counts'],
        split_file_sha256=integrity_before['split_sha256'], split_manifest='results/splits-seed32.json',
        split_manifest_sha256=manifest['sample_manifest_sha256'],
        test_sample_ids=[manifest['samples'][i]['id'] for i in manifest['indices']['test']],
        git_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        tracked_git_status=subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], text=True).strip(),
        source_sha256={str(p): sha(p) for pattern in ('recovery/*.py', 'src/*.py') for p in sorted(Path('.').glob(pattern))},
        command=shlex.join([sys.executable, '-m', 'recovery.application_train', *sys.argv[1:]]),
        environment_command='nix-shell recovery/audit-shell.nix', software=versions,
        preprocessing_resources=validation['resources'] if condition != 'real' else {'existing_real_cache_reused': True},
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), oom_attempts=[])
    result['independent_metric_validation'] = validate_result(result, manifest)
    if condition == 'real':
        exact = all(result[k] == reference[k] for k in
                    ('test_predictions', 'test_labels', 'accuracy', 'macro_f1', 'confusion_matrix', 'best_epoch', 'initial_state_sha256'))
        result['previous_real_exact_reproduction'] = exact
        if not exact:
            save(output_dir / 'STOP_BASELINE_MISMATCH.json', result)
            raise ValueError('STOP M: Real did not reproduce existing deterministic baseline')
    result['integrity_after_training'] = verify()
    save(output, result)
    with (output_dir / f'{condition}.txt').open('x') as handle:
        handle.write(LIMITATION + '\n\n' + json.dumps(result, indent=2) + '\n')
    print('SAVED', output, result['accuracy'], result['macro_f1'], flush=True)


if __name__ == '__main__':
    main()
