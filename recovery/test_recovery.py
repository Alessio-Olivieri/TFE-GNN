"""Boundary tests for extraction, leakage prevention and payload interventions."""
import collections
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import numpy as np
import torch

from recovery.audit import packets, tcp_packet
from recovery.data import grouped_split, payload_bytes, padded_graphs, collate
from recovery.model import RecoveredTFEGNN, OriginalSemanticsEncoder


def ipv4_packet(reverse=False, payload=b'abc', ip_options=b''):
    a, b = b'\x0a\x00\x00\x01', b'\x0a\x00\x00\x02'
    ports = (1234, 443)
    if reverse:
        a, b = b, a
        ports = ports[::-1]
    ihl = 20 + len(ip_options)
    ip = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl // 4, 0, ihl + 20 + len(payload),
                     1, 0, 64, 6, 0, a, b) + ip_options
    tcp = struct.pack('!HHIIBBHHH', *ports, 1, 1, 0x50, 0x18, 100, 0, 0)
    return ip + tcp + payload


def ng_block(kind, body):
    body += b'\0' * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack('<II', kind, size) + body + struct.pack('<I', size)


class ExtractionTests(unittest.TestCase):
    def test_bidirectional_tuple_and_headers(self):
        c = collections.Counter()
        a = tcp_packet(101, ipv4_packet(), c)
        b = tcp_packet(101, ipv4_packet(True), c)
        self.assertEqual(a[0], b[0])
        self.assertNotEqual(a[1], b[1])
        self.assertEqual(a[3], b'abc')
        self.assertEqual(len(a[2]), 28)  # IPv4+TCP minus addresses and ports
        self.assertEqual(a[2], list(ipv4_packet()[:12] + ipv4_packet()[24:40]))

    def test_ip_options_do_not_shift_port_removal(self):
        raw = ipv4_packet(ip_options=b'\x01\x01\x01\x01')
        record = tcp_packet(101, raw, collections.Counter())
        self.assertEqual(record[3], b'abc')
        self.assertEqual(record[2], list(raw[:12] + raw[20:24] + raw[28:44]))

    def test_ethernet_and_vlan(self):
        raw = ipv4_packet()
        ethernet = b'\x00' * 12 + b'\x08\x00' + raw
        vlan = b'\x00' * 12 + b'\x81\x00\x00\x01\x08\x00' + raw
        expected = tcp_packet(101, raw, collections.Counter())
        self.assertEqual(expected, tcp_packet(1, ethernet, collections.Counter()))
        self.assertEqual(expected, tcp_packet(1, vlan, collections.Counter()))

    def test_pcap_and_pcapng_equivalence(self):
        raw = ipv4_packet()
        classic = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        classic += struct.pack('<IIII', 3, 250000, len(raw), len(raw)) + raw
        ng = ng_block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
        ng += ng_block(1, struct.pack('<HHI', 101, 0, 65535))
        ng += ng_block(6, struct.pack('<IIIII', 0, 0, 3250000, len(raw), len(raw)) + raw)
        with tempfile.TemporaryDirectory() as tmp:
            p, q = Path(tmp) / 'a.pcap', Path(tmp) / 'b.pcap'
            p.write_bytes(classic)
            q.write_bytes(ng)
            self.assertEqual(list(packets(p)), list(packets(q)))

    def test_fragment_excluded(self):
        raw = bytearray(ipv4_packet())
        raw[6:8] = b'\x20\x00'
        counts = collections.Counter()
        self.assertIsNone(tcp_packet(101, raw, counts))
        self.assertEqual(counts['tcp_fragments_excluded'], 1)


class InterventionTests(unittest.TestCase):
    def test_random_length_padding_and_rng_isolation(self):
        np.random.seed(77)
        state = np.random.get_state()
        for length in (1, 30, 149, 150, 151, 1500):
            stored = [5] * min(length, 150)
            first = payload_bytes(stored, length, 'random', 32, 'sample', 0)
            self.assertEqual(len(first), 150)
            self.assertEqual(first[min(length, 150):], [256] * max(0, 150 - length))
            self.assertTrue(all(0 <= b <= 255 for b in first[:min(length, 150)]))
            self.assertEqual(first, payload_bytes(stored, length, 'random', 32, 'sample', 0))
            self.assertEqual(stored, [5] * min(length, 150))
        after = np.random.get_state()
        self.assertTrue(np.array_equal(state[1], after[1]))

    def test_random_happens_before_graph(self):
        real = payload_bytes([0] * 100, 100, 'real', 32, 'sample', 0)
        random = payload_bytes([0] * 100, 100, 'random', 32, 'sample', 0)
        a, b = padded_graphs([real], 150)[0], padded_graphs([random], 150)[0]
        self.assertGreater(b.num_nodes, a.num_nodes)

    def test_zero_preserves_length_boundary(self):
        value = payload_bytes([99] * 7, 7, 'zero', 32, 'sample', 0)
        self.assertEqual(value, [0] * 7 + [256] * 143)

    def test_graph_pmi_against_independent_matrix(self):
        from dataset import construct_graph_pyg
        sequence = [1, 2, 1, 3, 4, 3, 2, 5, 1, 1]
        windows = [sequence[i:i + 5] for i in range(len(sequence) - 4)]
        freq = np.zeros(257)
        pairs = np.zeros((257, 257))
        for window in windows:
            hist = np.bincount(window, minlength=257)
            freq += hist > 0
            pairs += np.outer(hist, hist)
        np.fill_diagonal(pairs, 0)
        expected = {(i, j) for i, j in zip(*np.nonzero(pairs))
                    if pairs[i, j] * len(windows) > freq[i] * freq[j]}
        graph = construct_graph_pyg(sequence, 5)
        actual = {(int(graph.x[i]), int(graph.x[j])) for i, j in graph.edge_index.T.tolist() if i != j}
        self.assertEqual(actual, expected)


class SplitAndModelTests(unittest.TestCase):
    @staticmethod
    def samples():
        result = [dict(id=f'{label}-{i}', label=label, capture=f'{label}/capture',
                       source_family=f'{label}/family', tuple_hash=f't{label}-{i}',
                       content_hash=f'c{label}-{i}') for label in range(6) for i in range(15)]
        result[1]['tuple_hash'] = result[0]['tuple_hash']
        result[2]['content_hash'] = result[1]['content_hash']
        return result

    def test_grouping_transitive_reproducible_and_complete(self):
        samples = self.samples()
        original = copy.deepcopy(samples)
        a, b = grouped_split(samples, 32), grouped_split(samples, 32)
        self.assertEqual(a, b)
        self.assertEqual(samples, original)
        self.assertEqual(len({r['split'] for r in a['samples'][:3]}), 1)
        indices = [i for split in a['indices'].values() for i in split]
        self.assertEqual(sorted(indices), list(range(len(samples))))
        self.assertTrue(all(count > 0 for split in a['counts'].values() for count in split.values()))

    def test_capture_split_refuses_insufficient_sources(self):
        with self.assertRaises(ValueError):
            grouped_split(self.samples(), 32, 'capture')

    def test_batch_cpu_and_model_gradients(self):
        torch.manual_seed(32)
        torch.set_num_threads(2)
        h = padded_graphs([[1, 2, 3, 4]], 40)
        p = padded_graphs([[8, 9, 10]], 150)
        batch = collate([(h, p, 0), (h, p, 1)])
        self.assertEqual(batch[0].num_graphs, 100)
        self.assertEqual(batch[0].x.device.type, 'cpu')
        model = RecoveredTFEGNN()
        output = model(*batch)
        self.assertEqual(tuple(output.shape), (2, 6))
        torch.nn.functional.cross_entropy(output, batch[2]).backward()
        self.assertTrue(torch.isfinite(model.cls.weight.grad).all())
        model.eval()
        model.payload_mode = 'header-only'
        with torch.no_grad():
            before = model(*batch)
            changed_payload = collate([(h, padded_graphs([[255] * 150], 150), 0), (h, p, 1)])
            after = model(*changed_payload)
        self.assertTrue(torch.equal(before, after))


if __name__ == '__main__':
    unittest.main()
