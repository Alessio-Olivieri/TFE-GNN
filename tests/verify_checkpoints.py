"""Optional integration regression using private saved checkpoints and graphs."""
import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import torch

from experiments.multiseed import independent_metrics
from src.data import load_flows
from src.model import TFEGNN
from src.train import dataloader, read_split, seed_all
from tests.fixtures.validated_model import RecoveredTFEGNN


def verify(checkpoint_root, data_root, transformed_root, device, receipt=None):
    seed_all(32)
    torch.set_num_threads(4)
    source = load_flows(data_root)
    manifest = read_split(source, Path('results/splits-seed32.json'), 32, 'flow')
    rows = []
    for family in ('payload_ablation', 'tls_ciphertext_ablation'):
        runs = json.loads(Path('results', family, 'runs.json').read_text())['runs']
        for result in runs:
            seed, condition = result['training_seed'], result['condition']
            mode = result.get('model_payload_mode', condition)
            if family == 'payload_ablation':
                checkpoint = checkpoint_root / 'multiseed' / f'seed_{seed}' / f'{mode}-{seed}-batch8.pt'
            else:
                checkpoint = checkpoint_root / 'application_ciphertext' / f'seed_{seed}' / condition / f'real-{seed}-batch8.pt'
            before = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
            old = RecoveredTFEGNN(mode).to(device).eval()
            new = TFEGNN(payload_mode=mode).to(device).eval()
            state = torch.load(checkpoint, map_location=device, weights_only=True)
            old.load_state_dict(state, strict=True)
            new.load_state_dict(state, strict=True)
            root = transformed_root if condition == 'tls12_gcm_randomized' else data_root
            samples = load_flows(root)
            args = SimpleNamespace(seed=seed, payload_seed=32, data=root,
                                   payload_mode=mode, workers=0, device=str(device))
            loader = dataloader(samples, manifest['indices']['test'], args, 8, False)
            predictions, labels = [], []
            with torch.no_grad():
                for header, payload, y in loader:
                    batch = header.to(device), payload.to(device), y.to(device)
                    a, b = old(*batch), new(*batch)
                    if not torch.equal(a, b):
                        raise AssertionError(f'{checkpoint}: old/new logits differ')
                    predictions.extend(b.argmax(1).cpu().tolist())
                    labels.extend(y.tolist())
            if labels != result['test_labels'] or predictions != result['test_predictions']:
                raise AssertionError(f'{checkpoint}: saved predictions differ')
            accuracy, f1, matrix = independent_metrics(labels, predictions)
            assert abs(accuracy - result['accuracy']) < 1e-12
            assert abs(f1 - result['macro_f1']) < 1e-12 and matrix == result['confusion_matrix']
            assert hashlib.sha256(checkpoint.read_bytes()).hexdigest() == before
            rows.append(dict(family=family, training_seed=seed, condition=condition,
                checkpoint_sha256=before, test_samples=len(labels), strict_load=True,
                logits_bitwise_equal=True, saved_predictions_identical=True,
                accuracy=accuracy, macro_f1=f1))
            if receipt:
                receipt.write_text(json.dumps(dict(device=str(device), training=False,
                    completed_runs=len(rows), runs=rows), indent=2) + '\n')
            print(f'{family}/{seed}/{condition}: PASS ({len(labels)} samples)', flush=True)
            del old, new, state
    assert len(rows) == 15
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint-root', type=Path, default=Path('checkpoints'))
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--transformed-data', type=Path, default=Path('data/application_ciphertext/transformed_seed32'))
    parser.add_argument('--device', default='cpu')
    parser.add_argument('--receipt', type=Path, help='Optional new JSON verification record')
    args = parser.parse_args()
    if args.receipt and args.receipt.exists():
        raise FileExistsError('Refusing to overwrite a verification record')
    rows = verify(args.checkpoint_root, args.data, args.transformed_data,
                  torch.device(args.device), args.receipt)
    print(f'All {len(rows)} checkpoints passed; no training performed.')


if __name__ == '__main__':
    main()
