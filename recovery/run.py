"""Reproducible original TFE-GNN pilot using the recovered student's PyG model."""
import argparse
import csv
import datetime
import gc
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import random
import shlex
import subprocess
import sys
import time

import numpy as np
import torch
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import DataLoader

from recovery.audit import CLASSES, SETTINGS
from recovery.data import MODES, GraphFlows, collate, grouped_split, load_flows, prepare_graphs
from recovery.model import RecoveredTFEGNN
from recovery.resources import ResourceMonitor


def seed_all(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.use_deterministic_algorithms(True)


def software():
    versions = {p: importlib.metadata.version(p) for p in
                ('torch', 'torch-geometric', 'numpy', 'scikit-learn', 'scapy', 'psutil')}
    versions.update(python=sys.version, platform=platform.platform(), cuda=torch.version.cuda,
                    cudnn=torch.backends.cudnn.version())
    try:
        versions['nvidia_smi'] = subprocess.check_output(
            ['nvidia-smi', '--query-gpu=name,driver_version,memory.total', '--format=csv'], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        versions['nvidia_smi'] = 'unavailable'
    return versions


def evaluate(model, loader, device):
    model.eval()
    ys, predictions, loss_sum = [], [], 0.0
    with torch.no_grad():
        for h, p, y in loader:
            h, p = h.to(device), p.to(device)
            y_cuda = y.to(device)
            logits = model(h, p, y_cuda)
            loss_sum += torch.nn.functional.cross_entropy(logits, y_cuda, reduction='sum').item()
            ys.extend(y.tolist())
            predictions.extend(logits.argmax(1).cpu().tolist())
    report = classification_report(ys, predictions, labels=list(range(6)),
                                   target_names=CLASSES, output_dict=True, zero_division=0)
    return report, confusion_matrix(ys, predictions, labels=list(range(6))).tolist(), loss_sum / len(ys), ys, predictions


def dataloader(samples, indices, args, batch_size, shuffle):
    generator = torch.Generator().manual_seed(args.seed)
    return DataLoader(GraphFlows(samples, indices, args.data / 'graphs', args.payload_mode, args.payload_seed),
                      batch_size=batch_size, shuffle=shuffle, generator=generator,
                      collate_fn=collate, num_workers=args.workers,
                      persistent_workers=args.workers > 0, pin_memory=args.device.startswith('cuda'),
                      worker_init_fn=seed_worker)


def seed_worker(worker_id):
    # PyTorch sets the worker's Torch seed from the loader generator already.
    worker_seed = torch.initial_seed() % 2**32
    random.seed(worker_seed)
    np.random.seed(worker_seed)


def read_split(samples, path, seed, grouping):
    """Validate a saved split without regenerating or modifying it."""
    manifest = json.loads(path.read_text())
    if manifest['seed'] != seed or manifest['grouping'] != grouping:
        raise ValueError('Existing split settings differ; refusing to silently change the split')
    records = manifest['samples']
    fingerprint = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
    if fingerprint != manifest['sample_manifest_sha256']:
        raise ValueError('Saved split manifest fingerprint does not match its contents')
    keys = ('id', 'label', 'capture', 'source_family', 'tuple_hash', 'content_hash')
    if len(samples) != len(records) or any(
            any(s[k] != r[k] for k in keys) for s, r in zip(samples, records)):
        raise ValueError('Dataset differs from saved split manifest')
    flattened = [i for indices in manifest['indices'].values() for i in indices]
    if sorted(flattened) != list(range(len(samples))):
        raise ValueError('Split indices must cover each sample exactly once')
    for split, indices in manifest['indices'].items():
        if indices != [i for i, r in enumerate(records) if r['split'] == split]:
            raise ValueError('Split indices differ from saved membership')
    for key in ('tuple_hash', 'content_hash', 'group_id'):
        membership = {}
        for record in records:
            previous = membership.setdefault(record[key], record['split'])
            if previous != record['split']:
                raise ValueError(f'{key} leakage in saved split')
    return manifest


def train_attempt(samples, manifest, args, batch_size, log):
    seed_all(args.seed)
    torch.set_num_threads(4)
    device = torch.device(args.device)
    if device.type == 'cuda':
        torch.cuda.empty_cache()
        torch.cuda.reset_peak_memory_stats()
    monitor = ResourceMonitor().start()
    model = RecoveredTFEGNN(args.payload_mode).to(device)
    initial_hash = hashlib.sha256(b''.join(v.detach().cpu().numpy().tobytes()
                                         for v in model.state_dict().values())).hexdigest()
    train_loader = dataloader(samples, manifest['indices']['train'], args, batch_size, True)
    val_loader = dataloader(samples, manifest['indices']['validation'], args, batch_size, False)
    accumulation = max(1, math.ceil(args.effective_batch_size / batch_size))
    steps_per_epoch = math.ceil(len(train_loader) / accumulation)
    steps = steps_per_epoch * args.epochs
    warmup = max(1, int(0.1 * steps))

    def lr_factor(step):
        if step < warmup:
            return step / warmup
        progress = min(1, (step - warmup) / max(1, steps - warmup))
        return 0.01 + 0.99 * (1 + math.cos(math.pi * progress)) / 2

    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=0)
    scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_factor)
    criterion = torch.nn.CrossEntropyLoss()
    checkpoint = args.checkpoints / f'{args.payload_mode}-{args.seed}-batch{batch_size}.pt'
    if checkpoint.exists():
        raise FileExistsError(f'Refusing to overwrite a checkpoint from another run: {checkpoint}')
    history, best_key, best_epoch = [], (-1.0, -float('inf')), None
    try:
        for epoch in range(1, args.epochs + 1):
            started = time.monotonic()
            model.train()
            optimizer.zero_grad(set_to_none=True)
            loss_sum = correct = seen = 0
            for i, (h, p, y) in enumerate(train_loader):
                h, p, y = h.to(device), p.to(device), y.to(device)
                logits = model(h, p, y)
                loss = criterion(logits, y)
                group_start = i // accumulation * accumulation
                group_samples = min(accumulation * batch_size,
                                    len(train_loader.dataset) - group_start * batch_size)
                (loss * len(y) / group_samples).backward()
                if (i + 1) % accumulation == 0 or i + 1 == len(train_loader):
                    optimizer.step()
                    optimizer.zero_grad(set_to_none=True)
                    scheduler.step()
                loss_sum += loss.item() * len(y)
                correct += (logits.argmax(1) == y).sum().item()
                seen += len(y)
                if i % 50 == 0:
                    log(f'epoch={epoch} minibatch={i}/{len(train_loader)} loss={loss.item():.4f}')
            report, _, val_loss, _, _ = evaluate(model, val_loader, device)
            val_f1 = report['macro avg']['f1-score']
            key = (val_f1, -val_loss)
            if key > best_key:
                best_key, best_epoch = key, epoch
                torch.save(model.state_dict(), str(checkpoint) + '.partial')
                Path(str(checkpoint) + '.partial').replace(checkpoint)
            row = dict(epoch=epoch, train_loss=loss_sum / seen, train_accuracy=correct / seen,
                       validation_loss=val_loss, validation_macro_f1=val_f1,
                       elapsed_seconds=time.monotonic() - started,
                       lr=optimizer.param_groups[0]['lr'])
            history.append(row)
            log(json.dumps(row))
        model.load_state_dict(torch.load(checkpoint, map_location=device, weights_only=True))
        # Test is first evaluated here, after all epochs and checkpoint selection.
        test_loader = dataloader(samples, manifest['indices']['test'], args, batch_size, False)
        report, matrix, test_loss, ys, predictions = evaluate(model, test_loader, device)
        resources = monitor.finish()
        if device.type == 'cuda':
            resources.update(peak_gpu_allocated_mib=torch.cuda.max_memory_allocated() / 2**20,
                             peak_gpu_reserved_mib=torch.cuda.max_memory_reserved() / 2**20,
                             gpu=torch.cuda.get_device_name(),
                             gpu_memory_total_mib=torch.cuda.get_device_properties(device).total_memory / 2**20)
        return dict(accuracy=report['accuracy'], macro_precision=report['macro avg']['precision'],
                    macro_recall=report['macro avg']['recall'], macro_f1=report['macro avg']['f1-score'],
                    per_class={c: report[c] for c in CLASSES}, confusion_matrix=matrix,
                    confusion_matrix_orientation='rows=true, columns=predicted; class order listed in classes',
                    test_loss=test_loss, best_epoch=best_epoch, history=history, resources=resources,
                    batch_size=batch_size, gradient_accumulation=accumulation,
                    effective_batch_size=batch_size * accumulation, initial_state_sha256=initial_hash,
                    checkpoint=str(checkpoint), test_labels=ys, test_predictions=predictions)
    except BaseException:
        monitor.finish()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payload-mode', choices=MODES, required=True)
    parser.add_argument('--seed', '--training-seed', dest='seed', type=int, default=32)
    parser.add_argument('--split-seed', type=int, default=32)
    parser.add_argument('--split-manifest', type=Path)
    parser.add_argument('--payload-seed', type=int,
                        help='Transformation/cache seed; defaults to training seed for legacy commands')
    parser.add_argument('--result-name', help='Output basename; existing files are never overwritten')
    parser.add_argument('--epochs', type=int, default=20)
    parser.add_argument('--batch-size', type=int, default=8)
    parser.add_argument('--effective-batch-size', type=int, default=32)
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--graph-workers', type=int, default=4)
    parser.add_argument('--device', default='cuda:0')
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--results', type=Path, default=Path('results'))
    parser.add_argument('--checkpoints', type=Path, default=Path('checkpoints/recovery'))
    parser.add_argument('--log-dir', type=Path, default=Path('logs/recovery'))
    parser.add_argument('--allow-shared-captures', action='store_true')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if args.payload_seed is None:
        args.payload_seed = args.seed
    if args.epochs < 1 or args.batch_size < 1:
        parser.error('epochs and batch size must be positive')
    args.results.mkdir(exist_ok=True, parents=True)
    args.checkpoints.mkdir(exist_ok=True, parents=True)
    samples = load_flows(args.data)
    manifest_path = args.split_manifest or args.results / f'splits-seed{args.split_seed}.json'
    grouping = 'flow' if args.allow_shared_captures else 'capture'
    if manifest_path.exists() or args.split_manifest is not None:
        manifest = read_split(samples, manifest_path, args.split_seed, grouping)
    else:
        manifest = grouped_split(samples, args.split_seed, grouping)
        with manifest_path.open('x') as f:
            json.dump(manifest, f, indent=2)
    print('PRELIMINARY:', manifest['limitation'], flush=True)
    print('Split counts:', json.dumps(manifest['counts']), flush=True)
    print('Split fingerprint:', manifest['sample_manifest_sha256'], flush=True)
    name = args.result_name or ('baseline' if args.payload_mode == 'real' else f'{args.payload_mode}-seed{args.seed}')
    output = args.results / f'{name}.json'
    if output.exists() and not args.prepare_only:
        raise FileExistsError(f'Refusing to overwrite existing results: {output}')
    prep_monitor = ResourceMonitor().start()
    prepare_graphs(samples, args.data / 'graphs', args.payload_mode, args.payload_seed, args.graph_workers)
    preprocessing_resources = prep_monitor.finish()
    receipt = args.results / f'preprocessing-{args.payload_mode}-seed{args.seed}.json'
    if not receipt.exists():
        with receipt.open('x') as f:
            json.dump(dict(settings=SETTINGS, resources=preprocessing_resources,
                           split_sha256=manifest['sample_manifest_sha256']), f, indent=2)
    if args.prepare_only:
        return
    if args.device.startswith('cuda') and not torch.cuda.is_available():
        raise RuntimeError('CUDA unavailable. Use the host Nix shell; CPU fallback is not automatic.')
    logdir = args.log_dir
    logdir.mkdir(parents=True, exist_ok=True)
    log_path = logdir / f'{args.payload_mode}-{args.seed}.log'
    with log_path.open('x', buffering=1) as log_file:
        def log(message):
            print(message, flush=True)
            print(message, file=log_file, flush=True)
        versions = software()
        log(json.dumps(dict(software=versions, counts=manifest['counts'], seed=args.seed)))
        batch = args.batch_size
        oom_attempts = []
        while True:
            try:
                result = train_attempt(samples, manifest, args, batch, log)
                break
            except torch.cuda.OutOfMemoryError as error:
                oom_attempts.append(dict(batch_size=batch, message=str(error)))
                if batch == 1:
                    raise
                batch = max(1, batch // 2)
                log(f'GPU OOM: restarting deterministically with batch size {batch}; architecture unchanged.')
                gc.collect()
                torch.cuda.empty_cache()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    tracked_status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], text=True).strip()
    source_hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                     for pattern in ('recovery/*.py', 'src/*.py') for p in sorted(Path('.').glob(pattern))}
    audit = json.loads((args.data / 'audit.json').read_text())
    result.update(condition=args.payload_mode, seed=args.seed, training_seed=args.seed,
                  split_seed=args.split_seed, payload_seed=args.payload_seed,
                  epochs_completed=len(result['history']),
                  effective_seeds=dict(python=args.seed, numpy=args.seed, torch_cpu=args.seed,
                                       torch_cuda=args.seed, dataloader_generator=args.seed,
                                       dataloader_workers='torch.initial_seed() modulo 2**32 for Python/NumPy',
                                       pythonhashseed=os.environ.get('PYTHONHASHSEED'),
                                       split=args.split_seed, payload_randomization=args.payload_seed),
                  payload_randomization=dict(applied=args.payload_mode == 'random', seed=args.payload_seed,
                      algorithm='NumPy default_rng / PCG64',
                      derivation='SHA256(f"{seed}:{sample_id}:{packet_ordinal}:payload"), first 16 bytes big endian',
                      distribution='uniform uint8 0..255; full original payload length before truncation/padding/graph',
                      graph_cache=str(args.data / 'graphs' / f'{args.payload_mode}-{args.payload_seed}')),
                  split_file_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                  split_group_counts={split: len({manifest['samples'][i]['group_id'] for i in indices})
                                      for split, indices in manifest['indices'].items()},
                  test_sample_ids=[manifest['samples'][i]['id'] for i in manifest['indices']['test']],
                  preliminary=True,
                  dataset='ISCX-VPN2016 local six-class captures', classes=CLASSES,
                  dataset_counts=audit['sample_counts'], split_counts=manifest['counts'],
                  split_sizes=manifest['sizes'], split_manifest=str(manifest_path),
                  split_manifest_sha256=manifest['sample_manifest_sha256'],
                  capture_disjoint=manifest['capture_disjoint'], limitation=manifest['limitation'],
                  preprocessing=SETTINGS, preprocessing_resources=preprocessing_resources,
                  software=versions, git_commit=commit, tracked_git_status=tracked_status,
                  source_sha256=source_hashes, command=shlex.join([sys.executable, '-m', 'recovery.run', *sys.argv[1:]]),
                  environment_command='nix-shell recovery/shell.nix',
                  deterministic_settings=dict(torch_deterministic_algorithms=True,
                      cudnn_deterministic=True, cudnn_benchmark=False, tf32=False,
                      cublas_workspace_config=os.environ.get('CUBLAS_WORKSPACE_CONFIG'),
                      torch_threads=4, dataloader_workers=args.workers),
                  timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  hyperparameters=dict(epochs=args.epochs, lr=0.01, lr_min=0.0001, warmup=0.1,
                                       embedding_size=64, hidden_features=128, dropout=0.2,
                                       label_smoothing=0, weight_decay=0, optimizer='Adam',
                                       precision='float32', checkpoint_selection='validation macro F1; ties validation loss'),
                  oom_attempts=oom_attempts)
    with output.open('x') as f:
        json.dump(result, f, indent=2)
    with (args.results / f'{name}.txt').open('x') as f:
        f.write('PRELIMINARY — ' + result['limitation'] + '\n\n')
        f.write(json.dumps(result, indent=2) + '\n')
    comparison = args.results / 'comparison.csv'
    existed = comparison.exists()
    with comparison.open('a', newline='') as f:
        columns = ['condition', 'seed', 'accuracy', 'macro_precision', 'macro_recall', 'macro_f1']
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore', lineterminator='\n')
        if not existed:
            writer.writeheader()
        writer.writerow(result)
    print('SAVED', output, {k: result[k] for k in ('accuracy', 'macro_f1')}, flush=True)


if __name__ == '__main__':
    main()
