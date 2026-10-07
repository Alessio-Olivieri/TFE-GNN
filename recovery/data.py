"""Shared grouped splits and CPU/disk graph preprocessing for every condition."""
import collections
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import sys

import numpy as np
import torch
from torch.utils.data import Dataset
from torch_geometric.data import Batch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dataset import construct_graph_pyg  # noqa: E402
from recovery.audit import CLASSES, SETTINGS  # noqa: E402

MODES = ('real', 'random', 'zero', 'header-only', 'payload-only')


def load_flows(root):
    with gzip.open(Path(root) / 'flows.json.gz', 'rt') as f:
        return json.load(f)


def payload_bytes(stored, original_length, mode, seed, sample_id, ordinal):
    """Transform actual bytes BEFORE truncation, padding, and graph construction.

    Real bytes beyond the 150-byte representation cap need not be stored.
    Random/zero synthesize the entire original-length byte sequence first.
    The local RNG never consumes training/ordering RNG state.
    """
    if mode == 'random':
        digest = hashlib.sha256(f'{seed}:{sample_id}:{ordinal}:payload'.encode()).digest()
        rng = np.random.default_rng(int.from_bytes(digest[:16], 'big'))
        value = rng.integers(0, 256, size=original_length, dtype=np.uint8).tolist()
    elif mode == 'zero':
        value = [0] * original_length
    else:
        value = list(stored)
    return value[:150] + [256] * max(0, 150 - len(value))


def grouped_split(samples, seed, grouping='flow'):
    """Union identical tuples and representations, including across captures.

    Identical canonical TCP endpoints are conservatively related even if ports
    could have been reused. Transitive closure prevents indirect duplicate leaks.
    Capture mode additionally groups capture families (a/b recordings together).
    """
    parent = list(range(len(samples)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        a, b = find(a), find(b)
        parent[max(a, b)] = min(a, b)

    keys = ('tuple_hash', 'content_hash') + (('source_family',) if grouping == 'capture' else ())
    for key in keys:
        seen = {}
        for i, sample in enumerate(samples):
            if sample[key] in seen:
                union(i, seen[sample[key]])
            else:
                seen[sample[key]] = i
    groups = collections.defaultdict(list)
    for i in range(len(samples)):
        groups[find(i)].append(i)
    # Allocate groups by label composition without examining any model results.
    # Retry deterministically only to ensure every class is represented in all
    # partitions; choose the smallest predefined count-imbalance objective.
    counts = np.bincount([s['label'] for s in samples], minlength=6)
    targets = np.asarray([0.70, 0.15, 0.15])[:, None] * counts
    best = None
    for attempt in range(128):
        rng = random.Random(seed + attempt)
        group_list = list(groups.values())
        rng.shuffle(group_list)
        group_list.sort(key=len, reverse=True)  # seeded tie order
        allocation = [[], [], []]
        actual = np.zeros((3, 6), dtype=int)
        for group in group_list:
            vector = np.bincount([samples[i]['label'] for i in group], minlength=6)
            scores = []
            for split in range(3):
                candidate = actual.copy()
                candidate[split] += vector
                scores.append(float(np.sum((candidate - targets) ** 2 / np.maximum(targets, 1))))
            chosen = min(range(3), key=lambda k: scores[k])
            allocation[chosen].extend(group)
            actual[chosen] += vector
        score = float(np.sum((actual - targets) ** 2 / np.maximum(targets, 1)))
        if (actual > 0).all() and (best is None or score < best[0]):
            best = (score, allocation, actual)
    if best is None:
        raise ValueError('Cannot put every class in all three grouped partitions. Additional independent sources are required.')
    _, allocation, actual = best
    names = ('train', 'validation', 'test')
    assignment = {i: name for name, indices in zip(names, allocation) for i in indices}
    group_ids = {i: hashlib.sha256(':'.join(sorted(samples[j]['id'] for j in group)).encode()).hexdigest()
                 for group in groups.values() for i in group}
    records = [dict(index=i, id=s['id'], label=s['label'], capture=s['capture'],
                    source_family=s['source_family'], tuple_hash=s['tuple_hash'],
                    content_hash=s['content_hash'], group_id=group_ids[i], split=assignment[i])
               for i, s in enumerate(samples)]
    for key in ('tuple_hash', 'content_hash', 'group_id'):
        locations = collections.defaultdict(set)
        for record in records:
            locations[record[key]].add(record['split'])
        assert all(len(v) == 1 for v in locations.values()), f'{key} leakage'
    shared = sorted(set.intersection(*(set(samples[i]['capture'] for i in ix) for ix in allocation)))
    fingerprint = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
    return dict(seed=seed, grouping=grouping, proportions_requested=[0.70, 0.15, 0.15],
                classes=CLASSES, sample_manifest_sha256=fingerprint, samples=records,
                indices={name: sorted(ix) for name, ix in zip(names, allocation)},
                counts={name: dict(zip(CLASSES, map(int, row))) for name, row in zip(names, actual)},
                sizes={name: len(ix) for name, ix in zip(names, allocation)},
                groups=len(groups), captures_present_in_all_three_splits=shared,
                preliminary=True, capture_disjoint=grouping == 'capture',
                limitation='Flow-disjoint pilot; capture-level leakage remains possible.' if grouping == 'flow' else '')


def padded_graphs(values, width):
    result = [construct_graph_pyg(list(v[:width]) + [256] * max(0, width - len(v)), 5) for v in values[:50]]
    dummy = construct_graph_pyg([256] * width, 5)
    return result + [dummy] * (50 - len(result))


def graph_job(job):
    root, mode, seed, sample = job
    torch.set_num_threads(1)
    root = Path(root)
    hp = root / 'headers' / (sample['id'] + '.pt')
    pp = root / f'{mode}-{seed}' / (sample['id'] + '.pt')
    if not hp.exists():
        graphs = padded_graphs(sample['headers'], 40)
        torch.save(graphs, str(hp) + '.partial')
        os.rename(str(hp) + '.partial', hp)
    if mode != 'header-only' and not pp.exists():
        payloads = [payload_bytes(p, length, mode, seed, sample['id'], i)
                    for i, (p, length) in enumerate(zip(sample['payloads'], sample['payload_lengths']))]
        torch.save(padded_graphs(payloads, 150), str(pp) + '.partial')
        os.rename(str(pp) + '.partial', pp)
    return sample['id']


def prepare_graphs(samples, root, mode, seed, workers=4):
    root = Path(root)
    (root / 'headers').mkdir(parents=True, exist_ok=True)
    (root / f'{mode}-{seed}').mkdir(parents=True, exist_ok=True)
    jobs = ((str(root), mode, seed, s) for s in samples)
    # Spawn avoids inheriting any CUDA context from the parent.
    import multiprocessing as mp
    with ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context('spawn')) as pool:
        for i, _ in enumerate(pool.map(graph_job, jobs, chunksize=4), 1):
            if i % 100 == 0 or i == len(samples):
                print(f'Graphs {mode}: {i}/{len(samples)} flows', flush=True)


class GraphFlows(Dataset):
    def __init__(self, samples, indices, root, mode, seed):
        self.samples = samples
        self.indices = indices
        self.root = Path(root)
        self.mode = mode
        self.seed = seed

    def __len__(self):
        return len(self.indices)

    @staticmethod
    @lru_cache(maxsize=32)
    def load(path):
        # Only locally generated graph files are loaded. They stay on CPU.
        return torch.load(path, map_location='cpu', weights_only=False)

    def __getitem__(self, index):
        sample = self.samples[self.indices[index]]
        h = self.load(str(self.root / 'headers' / (sample['id'] + '.pt')))
        p = h if self.mode == 'header-only' else self.load(str(
            self.root / f'{self.mode}-{self.seed}' / (sample['id'] + '.pt')))
        return h, p, sample['label']


def collate(batch):
    h, p, y = zip(*batch)
    return (Batch.from_data_list([g for seq in h for g in seq]),
            Batch.from_data_list([g for seq in p for g in seq]),
            torch.tensor(y, dtype=torch.long))
