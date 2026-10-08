"""Scientific-stop, acquisition-isolation, and raw-to-model tracing tests."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from src.capture import CLASSES, tcp_packet
from experiments.capture_audit import (acquisition_key, assess_feasibility,
                                    validate_assignment, scan_capture, refine_capture_groups)
from experiments.capture_audit_report import ipv6_transport, coverage_status, group_evidence
from tests.test_preprocessing import ipv4_packet
import collections


class AcquisitionTests(unittest.TestCase):
    def test_ab_and_overlapping_audio_pairs_grouped(self):
        for a, b in [('Chat/vpn_skype_chat1a.pcap', 'Chat/vpn_skype_chat1b.pcap'),
                     ('Email/vpn_email2a.pcap', 'Email/vpn_email2b.pcap'),
                     ('FileTransfer/vpn_sftp_A.pcap', 'FileTransfer/vpn_sftp_B.pcap'),
                     ('VoIP/vpn_hangouts_audio1.pcap', 'VoIP/vpn_hangouts_audio2.pcap'),
                     ('VoIP/vpn_skype_audio1.pcap', 'VoIP/vpn_skype_audio2.pcap')]:
            self.assertEqual(acquisition_key(a), acquisition_key(b))

    def test_different_activities_not_merged_by_class(self):
        self.assertNotEqual(acquisition_key('Chat/vpn_aim_chat1a.pcap'),
                            acquisition_key('Chat/vpn_skype_chat1a.pcap'))

    def test_single_p2p_source_stops_even_if_other_classes_have_many_groups(self):
        rows = [dict(capture_group_id=f'{c}/{i}', sample_counts={c: 1})
                for c in CLASSES for i in range(1 if c == 'P2P' else 4)]
        result = assess_feasibility(rows)
        self.assertEqual(result['protocol'], 'STOP')
        self.assertEqual(result['blocking_classes'], {'P2P': ['P2P/0']})
        self.assertFalse(result['training_permitted'])

    def test_candidate_counts_do_not_certify_independence(self):
        for number, choice in ((2, 'candidate_grouped_cv'), (3, 'candidate_three_way')):
            rows = [dict(capture_group_id=f'{c}/{i}', sample_counts={c: 1})
                    for c in CLASSES for i in range(number)]
            result = assess_feasibility(rows)
            self.assertEqual(result['protocol'], choice)
            self.assertFalse(result['genuine_independence_certified'])
            self.assertFalse(result['training_permitted'])

    def test_grouping_and_decision_independent_of_traversal_order(self):
        rows = [dict(capture_group_id=acquisition_key(p), sample_counts={p.split('/')[0]: 1})
                for p in ('Email/vpn_email2a.pcap', 'Email/vpn_email2b.pcap', 'P2P/vpn_bittorrent.pcap')]
        self.assertEqual(assess_feasibility(rows), assess_feasibility(list(reversed(rows))))

    def test_capture_three_way_isolation(self):
        samples = [dict(id=str(i), label=i % 6, capture=f'cap{i//2}') for i in range(6)]
        rows = [s | dict(capture_group_id=s['capture']) for s in samples]
        good = {str(i): ('train', 'validation', 'test')[i//2] for i in range(6)}
        self.assertTrue(validate_assignment(rows, good, samples))
        for partition in ('validation', 'test'):
            bad = dict(good, **{'0': partition})
            with self.assertRaises(ValueError):
                validate_assignment(rows, bad, samples)

    def test_fold_isolation_and_full_coverage(self):
        samples = [dict(id=str(i), label=i, capture=f'cap{i//2}') for i in range(4)]
        rows = [s | dict(capture_group_id=s['capture']) for s in samples]
        for fold in (0, 1):
            assignments = {s['id']: 'test' if int(s['id'])//2 == fold else 'train' for s in samples}
            self.assertTrue(validate_assignment(rows, assignments, samples))
            assignments['0'] = assignments['2']
            with self.assertRaises(ValueError):
                validate_assignment(rows, assignments, samples)

    def test_missing_duplicate_records_and_changed_labels_rejected(self):
        samples = [dict(id='a', label=0, capture='a'), dict(id='b', label=1, capture='b')]
        rows = [s | dict(capture_group_id=s['capture']) for s in samples]
        assignments = {'a': 'train', 'b': 'test'}
        for bad in (rows[:1], [rows[0], rows[0]], [rows[0] | dict(label=2), rows[1]]):
            with self.assertRaises(ValueError):
                validate_assignment(bad, assignments, samples)

    def test_trace_matches_cached_bytes_and_preserves_pcap(self):
        raw = ipv4_packet(payload=b'GET / HTTP/1.1\r\n\r\n')
        pair, _, header, payload, _ = tcp_packet(101, raw, collections.Counter())
        sample = dict(id='a', capture='Chat/a.pcap', tuple_hash=hashlib.sha256(b''.join(pair)).hexdigest(),
                      headers=[header], payloads=[list(payload)], payload_lengths=[len(payload)])
        classic = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        classic += struct.pack('<IIII', 3, 0, len(raw), len(raw)) + raw
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'a.pcap'
            path.write_bytes(classic)
            before = path.read_bytes()
            scan, selected, flows = scan_capture(path, 'Chat/a.pcap', [sample])
            self.assertEqual(scan['counts']['model_real_payload_bytes'], len(payload))
            self.assertEqual(scan['counts']['raw_packets'], 1)
            self.assertEqual(list(selected), [1])
            self.assertEqual(flows[0]['selected'][0]['payload'], payload)
            self.assertEqual(path.read_bytes(), before)
            changed = copy.deepcopy(sample)
            changed['payloads'] = [[1]]
            with self.assertRaises(ValueError):
                scan_capture(path, 'Chat/a.pcap', [changed])

    def test_ipv6_transport_counts_extensions_without_guessing_fragments(self):
        packet = bytearray(48)
        packet[0], packet[6] = 0x60, 17
        self.assertEqual(ipv6_transport(packet), 17)
        packet[6], packet[40] = 0, 6
        self.assertEqual(ipv6_transport(packet), 6)
        packet[6], packet[40], packet[43] = 44, 17, 8
        self.assertIsNone(ipv6_transport(packet))
        self.assertIsNone(ipv6_transport(packet[:39]))

    def test_overlapping_acquisition_evidence_and_unassessed_coverage(self):
        captures = [dict(source_pcap=f'Email/vpn_email2{x}.pcap', capture_group_id='Email/vpn_email2',
                         labels=['Email'], usable_samples=1, group_reason='related activity and overlap',
                         first_timestamp=i, last_timestamp=i + 10,
                         stage_counts=dict(usable_samples=1, raw_packets=2, model_unique_source_packets=2,
                                           model_payload_packets=1, model_real_payload_bytes=12),
                         protocol_dissector={'model_source_packet_protocol_labels': {'tls': 2}})
                    for i, x in enumerate(('a', 'b'))]
        evidence = group_evidence(captures)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]['relationships'][0]['overlap_seconds'], 9)
        self.assertFalse(evidence[0]['permitted_to_subdivide'])
        coverage = coverage_status(captures)
        self.assertEqual(coverage['total_model_payload_bytes'], 24)
        self.assertFalse(coverage['range_parser_executed'])
        for row in coverage['by_scope']:
            self.assertIsNone(row['confirmed_ciphertext_bytes'])
            self.assertIsNone(row['unknown_bytes'])
            self.assertEqual(row['unassessed_bytes'], row['model_payload_bytes'])

    def test_graph_pmi_has_no_cross_packet_fitted_state(self):
        from src.data import padded_graphs
        import torch
        before = padded_graphs([[1, 2, 3, 1, 2, 4, 1, 4]], 40)[0]
        padded_graphs([[20, 21, 22, 23, 24] * 8], 40)
        after = padded_graphs([[1, 2, 3, 1, 2, 4, 1, 4]], 40)[0]
        self.assertTrue(torch.equal(before.x, after.x))
        self.assertTrue(torch.equal(before.edge_index, after.edge_index))

    def test_related_flows_merge_acquisition_groups_transitively_and_deterministically(self):
        inventory = [dict(source_pcap=f'Chat/{k}.pcap', capture_group_id=f'Chat/{k}', labels=['Chat'])
                     for k in ('a', 'b', 'c', 'd')]
        samples = [dict(id=str(i), capture=f'Chat/{capture}.pcap', tuple_hash=tuple_hash, content_hash=content)
                   for i, (capture, tuple_hash, content) in enumerate(
                       [('a', 'ab', 'a'), ('b', 'ab', 'b'), ('b', 'bc', 'b2'),
                        ('c', 'bc', 'c'), ('d', 'other', 'd')])]
        refined, links = refine_capture_groups(inventory, samples)
        groups = {c['source_pcap']: c['capture_group_id'] for c in refined}
        self.assertEqual(groups['Chat/a.pcap'], groups['Chat/c.pcap'])
        self.assertNotEqual(groups['Chat/a.pcap'], groups['Chat/d.pcap'])
        reverse, reversed_links = refine_capture_groups(list(reversed(inventory)), list(reversed(samples)))
        self.assertEqual(groups, {c['source_pcap']: c['capture_group_id'] for c in reverse})
        self.assertEqual(links, reversed_links)
        self.assertEqual(inventory[0]['capture_group_id'], 'Chat/a')
        self.assertTrue(all(r['labels'] == ['Chat'] for r in refined))


if __name__ == '__main__':
    unittest.main()
