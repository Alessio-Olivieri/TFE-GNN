"""Protocol-state and exact-offset tests before any ciphertext transformation."""
import unittest

from recovery.application_tls import (Uncertain, records, reassemble, tls_ranges, project, classify_flow)


def record(kind, body, version=0x0303):
    return bytes([kind]) + version.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, 'big') + body


def fixture(suite=0xc02f):
    base = b'\x03\x03' + bytes(32) + b'\x00'
    ch = handshake(1, base + b'\x00\x02' + suite.to_bytes(2, 'big') + b'\x01\x00')
    sh = handshake(2, base + suite.to_bytes(2, 'big') + b'\x00')
    finished = record(22, bytes(8) + bytes(range(16)) + bytes(16))
    data = record(23, bytes(8) + bytes(range(64)) + bytes(16))
    return [record(22, ch) + record(20, b'\x01') + finished + data,
            record(22, sh) + record(20, b'\x01') + finished + data]


def flow_fixture(streams, cut=70):
    selected = []
    for d, stream in enumerate(streams):
        for i, start in enumerate(range(0, len(stream), cut)):
            selected.append(dict(frame=len(selected) + 1, packet_index=len(selected),
                payload_ordinal=len(selected), direction=d, seq=100 + start,
                payload=stream[start:start + cut], sample_id='a'))
    return dict(selected=selected, syn=[{100}, {100}])


class TLSTests(unittest.TestCase):
    def test_gcm_separates_nonce_ciphertext_tag_and_record_framing(self):
        result = tls_ranges(fixture())
        self.assertEqual(result['protocol'], 'TLS1.2_AES_GCM')
        self.assertEqual(len(result['records']), 4)
        for witness in result['records']:
            self.assertEqual(witness['nonce_stream_range'][1] - witness['nonce_stream_range'][0], 8)
            self.assertEqual(witness['tag_stream_range'][1] - witness['tag_stream_range'][0], 16)
            self.assertEqual(witness['ciphertext_stream_range'][0], witness['stream_start'] + 13)

    def test_cross_packet_multiple_record_offsets_are_exact_and_partition_bytes(self):
        flow = flow_fixture(fixture(), cut=17)
        result = classify_flow(flow)
        self.assertEqual(result['protocol'], 'TLS1.2_AES_GCM')
        total = sum(p['byte_counts']['ciphertext'] for p in result['packets'])
        self.assertEqual(total, 160)  # 2 directions * (Finished 16 + application 64)
        for packet in result['packets']:
            self.assertEqual(sum(packet['byte_counts'].values()), packet['retained_payload_bytes'])
        self.assertEqual(project([(10, 30, 'ciphertext')], 20, 150),
                         [dict(start=0, end=10, kind='ciphertext')])

    def test_truncation_counts_only_real_model_bytes(self):
        result = classify_flow(flow_fixture(fixture(), cut=1000))
        self.assertTrue(all(p['retained_payload_bytes'] == 150 for p in result['packets']))
        self.assertLess(sum(p['byte_counts']['ciphertext'] for p in result['packets']), 160)

    def test_fragmented_handshake_is_reassembled_across_tls_records(self):
        streams = fixture()
        first = records(streams[0])[0]
        streams[0] = record(22, first['body'][:7]) + record(22, first['body'][7:]) + streams[0][first['end']:]
        self.assertEqual(tls_ranges(streams)['protocol'], 'TLS1.2_AES_GCM')

    def test_incomplete_final_record_body_is_never_ciphertext(self):
        full = fixture()
        full[0] = full[0][:-10]
        result = tls_ranges(full)
        self.assertEqual(len([r for r in result['records'] if r['direction'] == 0]), 1)

    def test_missing_or_unoffered_hellos_rejected(self):
        streams = fixture()
        streams[1] = streams[1][records(streams[1])[0]['end']:]
        with self.assertRaises(Uncertain):
            tls_ranges(streams)
        streams = fixture()
        streams[1] = streams[1].replace(b'\xc0\x2f', b'\xc0\x30', 1)
        with self.assertRaises(Uncertain):
            tls_ranges(streams)

    def test_missing_ccs_application_before_ccs_and_renegotiation_rejected(self):
        streams = fixture()
        streams[0] = streams[0].replace(record(20, b'\x01'), b'', 1)
        with self.assertRaises(Uncertain):
            tls_ranges(streams)
        streams = fixture()
        streams[0] += record(22, bytes(40))
        with self.assertRaises(Uncertain):
            tls_ranges(streams)

    def test_cbc_is_unsupported_never_guessed_ciphertext_or_padding(self):
        result = classify_flow(flow_fixture(fixture(0x002f)))
        self.assertEqual(result['protocol'], 'TLS_UNSUPPORTED')
        self.assertEqual(sum(p['byte_counts']['ciphertext'] for p in result['packets']), 0)
        self.assertGreater(sum(p['byte_counts']['unsupported'] for p in result['packets']), 0)

    def test_tls13_negotiation_is_not_parsed_as_tls12_gcm(self):
        streams = fixture()
        sh = records(streams[1])[0]
        body = sh['body'][4:] + b'\x00\x06\x00\x2b\x00\x02\x03\x04'
        streams[1] = record(22, handshake(2, body)) + streams[1][sh['end']:]
        result = tls_ranges(streams)
        self.assertEqual(result['protocol'], 'TLS_UNSUPPORTED')
        self.assertEqual(result['records'], [])

    def test_reassembly_order_retransmission_wraparound_and_conflict(self):
        a = dict(frame=1, seq=2**32 - 3, payload=b'abcde')
        b = dict(frame=2, seq=2, payload=b'fgh')
        for values in ([a, b, a], [b, a]):
            self.assertEqual(reassemble(values, {2**32 - 3})[0], b'abcdefgh')
        with self.assertRaises(Uncertain):
            reassemble([a, dict(frame=2, seq=2**32 - 1, payload=b'BAD')], {2**32 - 3})
        with self.assertRaises(Uncertain):
            reassemble([b], {2**32 - 3})
        with self.assertRaises(Uncertain):
            reassemble([a], {1, 2})

    def test_missing_syn_never_resynchronizes_from_tls_looking_bytes(self):
        flow = flow_fixture(fixture())
        flow['syn'] = [set(), set()]
        result = classify_flow(flow)
        self.assertEqual(result['protocol'], 'UNKNOWN')
        self.assertTrue(all(p['byte_counts']['ciphertext'] == 0 for p in result['packets']))

    def test_ssh_setup_banner_known_but_encrypted_boundary_not_guessed(self):
        result = classify_flow(flow_fixture([b'SSH-2.0-example\r\n' + bytes(200), b'SSH-2.0-server\r\n' + bytes(200)]))
        self.assertEqual(result['protocol'], 'SSH_UNSUPPORTED')
        self.assertTrue(all(p['byte_counts']['ciphertext'] == 0 for p in result['packets']))
        self.assertGreater(sum(p['byte_counts']['plaintext'] for p in result['packets']), 0)


if __name__ == '__main__':
    unittest.main()
