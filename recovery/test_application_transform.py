"""Ciphertext-only mutation, deterministic identities and graph rebuild tests."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import torch

from recovery.application_transform import randomize, transformed_samples
from recovery.data import graph_job, padded_graphs


def fixture():
    packet = dict(packet_index=12, payload_ordinal=0, frame=42, retained_payload_bytes=128, payload_length=128,
        ranges=[dict(start=0, end=13, kind='framing'), dict(start=13, end=77, kind='ciphertext'),
                dict(start=77, end=93, kind='authentication'), dict(start=93, end=100, kind='plaintext'),
                dict(start=100, end=128, kind='unknown')], byte_counts=dict(ciphertext=64))
    return packet


class TransformTests(unittest.TestCase):
    def test_same_seed_deterministic_copy_preserves_all_non_ciphertext(self):
        original = list(range(128))
        packet = fixture()
        a = randomize(original, 'capture', 'flow', packet, 32)
        self.assertEqual(a, randomize(original, 'capture', 'flow', packet, 32))
        self.assertEqual(original, list(range(128)))
        self.assertEqual(len(a), len(original))
        self.assertTrue(all(a[i] == original[i] for i in list(range(13)) + list(range(77, 128))))
        self.assertNotEqual(a[13:77], original[13:77])

    def test_seed_packet_capture_and_flow_changes_use_distinct_streams(self):
        p = fixture()
        values = [randomize(list(range(128)), c, f, q, seed)[13:77]
                  for c, f, q, seed in [('c', 'f', p, 32), ('c', 'f', p, 42), ('c2', 'f', p, 32),
                                      ('c', 'f2', p, 32), ('c', 'f', {**p, 'packet_index': 13}, 32)]]
        self.assertEqual(len({bytes(v) for v in values}), len(values))

    def test_range_order_does_not_affect_stream_and_unknown_ranges_unchanged(self):
        p = fixture()
        self.assertEqual(randomize(list(range(128)), 'c', 'f', p),
                         randomize(list(range(128)), 'c', 'f', {**p, 'ranges': list(reversed(p['ranges']))}))
        p['ranges'] = [dict(start=0, end=128, kind='unknown')]
        self.assertEqual(randomize(list(range(128)), 'c', 'f', p), list(range(128)))

    def test_invalid_overlapping_ranges_and_lengths_rejected(self):
        for ranges in ([dict(start=-1, end=2, kind='ciphertext')],
                       [dict(start=0, end=129, kind='ciphertext')],
                       [dict(start=0, end=40, kind='ciphertext'), dict(start=20, end=60, kind='ciphertext')]):
            with self.assertRaises(ValueError):
                randomize(list(range(128)), 'c', 'f', {**fixture(), 'ranges': ranges})
        with self.assertRaises(ValueError):
            randomize([1], 'c', 'f', fixture())

    def test_source_file_and_source_hash_remain_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'source.pcap'
            source.write_bytes(bytes(range(128)))
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            randomize(list(source.read_bytes()), 'c', 'f', fixture())
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)

    def test_samples_labels_headers_lengths_order_and_identity_preserved(self):
        samples = [dict(id='a', capture='c', label=2, headers=[[1, 2, 3]], payloads=[list(range(128))],
                        payload_lengths=[128], packet_lengths=[168], source_family='family', content_hash='source')]
        ranges = [dict(id='a', capture='c', capture_id='sha', label=2, split='test', protocol='TLS1.2_AES_GCM', packets=[fixture()])]
        before = copy.deepcopy(samples)
        derived, audit = transformed_samples(samples, ranges)
        self.assertEqual(samples, before)
        self.assertTrue(all(derived[0][k] == samples[0][k] for k in samples[0] if k != 'payloads'))
        self.assertEqual(audit[0]['targeted_bytes'], 64)
        self.assertEqual(audit[0]['split'], 'test')
        self.assertGreater(audit[0]['changed_bytes'], 0)
        self.assertEqual(len(derived[0]['payloads'][0]), 128)
        for bad in ([{**ranges[0], 'id': 'different'}], [{**ranges[0], 'label': 3}]):
            with self.assertRaises(ValueError):
                transformed_samples(samples, bad)

    def test_rebuilt_payload_graph_uses_transformed_bytes_in_separate_cache(self):
        packet = fixture()
        original = [0] * 128
        transformed = randomize(original, 'c', 'f', packet)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'real-cache'
            derived = Path(tmp) / 'transformed-cache'
            sample = dict(id='a', headers=[[1, 2]], payloads=[original], payload_lengths=[128])
            for root in (source, derived):
                (root / 'headers').mkdir(parents=True)
                (root / 'real-32').mkdir()
            graph_job((str(source), 'real', 32, sample))
            old_path = source / 'real-32/a.pt'
            before = hashlib.sha256(old_path.read_bytes()).hexdigest()
            graph_job((str(derived), 'real', 32, {**sample, 'payloads': [transformed]}))
            old = torch.load(old_path, weights_only=False)[0]
            new = torch.load(derived / 'real-32/a.pt', weights_only=False)[0]
            expected = padded_graphs([transformed], 150)[0]
            self.assertTrue(torch.equal(expected.x, new.x) and torch.equal(expected.edge_index, new.edge_index))
            self.assertFalse(torch.equal(old.x, new.x) and torch.equal(old.edge_index, new.edge_index))
            self.assertEqual(hashlib.sha256(old_path.read_bytes()).hexdigest(), before)

    def test_python_hash_seed_does_not_affect_transformation(self):
        code = ('import json;from recovery.application_transform import randomize;'
                'p=' + repr(fixture()) + ';print(json.dumps(randomize(list(range(128)),"c","f",p)))')
        outputs = [subprocess.check_output([sys.executable, '-c', code], text=True,
                                           env={**os.environ, 'PYTHONHASHSEED': str(seed)}) for seed in (1, 999)]
        self.assertEqual(outputs[0], outputs[1])


if __name__ == '__main__':
    unittest.main()
