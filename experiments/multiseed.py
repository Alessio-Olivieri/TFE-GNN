"""Paired payload ablations with fixed split and input-transformation seeds."""
import argparse
from pathlib import Path
import statistics
import subprocess
import sys

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--device', default='cuda:0')
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Use a fresh output directory; published results are read-only')
    args.output.mkdir(parents=True)
    for seed in (32, 42, 52):
        for mode in ('real', 'random', 'header-only'):
            root = args.output / f'seed_{seed}' / mode
            subprocess.run([sys.executable, '-m', 'src.train',
                '--data', str(args.data), '--payload-mode', mode,
                '--training-seed', str(seed), '--split-seed', '32', '--payload-seed', '32',
                '--split-manifest', 'results/splits-seed32.json',
                '--epochs', '20', '--batch-size', '8', '--effective-batch-size', '32',
                '--allow-shared-captures', '--device', args.device,
                '--results', str(root), '--result-name', 'run',
                '--checkpoints', str(root / 'checkpoints'), '--log-dir', str(root / 'logs')], check=True)


if __name__ == '__main__':
    main()
