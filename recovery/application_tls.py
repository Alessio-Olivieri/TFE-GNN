"""Conservative TLS 1.2 AES-GCM interpretation, with exact packet offsets.

New project analysis code, based on RFC 5246/5288/5289. No decryption, entropy
classification, transformation, model code, source writes or port heuristics.
Unsupported/missing state remains untouched. Offsets are half-open.
"""
import collections
import re

VERSION = 'tls12-gcm-exact-prefix-v1'
GCM_SUITES = frozenset(range(0x009c, 0x00a8)) | frozenset(range(0xc02b, 0xc033))
KINDS = ('ciphertext', 'framing', 'plaintext', 'authentication', 'padding', 'unknown', 'unsupported')


class Uncertain(ValueError):
    pass


def reassemble(segments, origins):
    """Interpret selected full TCP payloads; retain packet-to-sequence mapping.

    Starts at a captured SYN's sequence+1. Reject tuple reuse, gaps, conflicts,
    missing beginnings, and segments before the SYN. Identical retransmissions
    are permitted and each original packet keeps its own mapped offsets.
    """
    if len(origins) != 1:
        raise Uncertain('missing_or_multiple_syn_origins')
    origin = next(iter(origins))
    mapped = []
    for packet in segments:
        start = (packet['seq'] - origin) % 2**32
        if start > 4 * 1024 * 1024 or start + len(packet['payload']) > 4 * 1024 * 1024:
            raise Uncertain('sequence_outside_bounded_prefix')
        mapped.append((start, packet))
    stream = bytearray()
    for start, packet in sorted(mapped, key=lambda r: (r[0], r[1]['frame'])):
        data = packet['payload']
        if start > len(stream):
            raise Uncertain('tcp_gap_or_missing_stream_start')
        overlap = min(len(data), len(stream) - start)
        if stream[start:start + overlap] != data[:overlap]:
            raise Uncertain('conflicting_tcp_overlap')
        stream.extend(data[overlap:])
    return bytes(stream), mapped


def records(stream):
    result, offset = [], 0
    while len(stream) - offset >= 5:
        kind = stream[offset]
        version = int.from_bytes(stream[offset + 1:offset + 3], 'big')
        length = int.from_bytes(stream[offset + 3:offset + 5], 'big')
        if kind not in (20, 21, 22, 23) or version not in (0x0301, 0x0302, 0x0303) or length > 18432:
            raise Uncertain('not_a_complete_supported_tls_record_stream')
        end = offset + 5 + length
        if end > len(stream):
            break  # Entire incomplete record remains unknown, including its body.
        result.append(dict(start=offset, end=end, kind=kind, version=version,
                           length=length, body=stream[offset + 5:end]))
        offset = end
    if not result or result[0]['kind'] != 22:
        raise Uncertain('no_initial_plaintext_handshake_record')
    return result


def handshakes(record_list):
    """Reassemble plaintext handshake messages only, before ChangeCipherSpec."""
    buffer, offsets, result = bytearray(), [], []
    for record in record_list:
        if record['kind'] == 20:
            if buffer:
                raise Uncertain('incomplete_handshake_before_ccs')
            break
        if record['kind'] == 23:
            raise Uncertain('application_data_before_ccs')
        if record['kind'] != 22:
            continue
        buffer.extend(record['body'])
        offsets.extend(range(record['start'] + 5, record['end']))
        while len(buffer) >= 4:
            length = int.from_bytes(buffer[1:4], 'big')
            if length > 2 * 1024 * 1024:
                raise Uncertain('invalid_handshake_length')
            if len(buffer) < 4 + length:
                break
            result.append(dict(kind=buffer[0], body=bytes(buffer[4:4 + length]),
                               offsets=offsets[:4 + length]))
            del buffer[:4 + length]
            del offsets[:4 + length]
    return result


def extensions(body, offset):
    if offset == len(body):
        return {}
    if offset + 2 > len(body):
        raise Uncertain('truncated_hello_extensions')
    length = int.from_bytes(body[offset:offset + 2], 'big')
    end, offset = offset + 2 + length, offset + 2
    if end != len(body):
        raise Uncertain('hello_extension_length_mismatch')
    result = {}
    while offset < end:
        if offset + 4 > end:
            raise Uncertain('truncated_extension_header')
        kind = int.from_bytes(body[offset:offset + 2], 'big')
        length = int.from_bytes(body[offset + 2:offset + 4], 'big')
        offset += 4
        if offset + length > end or kind in result:
            raise Uncertain('invalid_or_duplicate_hello_extension')
        result[kind] = body[offset:offset + length]
        offset += length
    return result


def hello(message):
    body = message['body']
    if len(body) < 35 or body[34] > 32:
        raise Uncertain('truncated_or_invalid_hello')
    version, offset = int.from_bytes(body[:2], 'big'), 35 + body[34]
    if offset > len(body):
        raise Uncertain('truncated_session_id')
    if message['kind'] == 1:
        if offset + 2 > len(body):
            raise Uncertain('missing_offered_ciphers')
        size = int.from_bytes(body[offset:offset + 2], 'big')
        offset += 2
        if size < 2 or size % 2 or offset + size >= len(body):
            raise Uncertain('invalid_offered_ciphers')
        suites = [int.from_bytes(body[i:i + 2], 'big') for i in range(offset, offset + size, 2)]
        offset += size
        size = body[offset]
        offset += 1
        if size < 1 or offset + size > len(body):
            raise Uncertain('invalid_compression_offer')
        compression = list(body[offset:offset + size])
        offset += size
        return dict(version=version, suites=suites, compressions=compression, extensions=extensions(body, offset))
    if offset + 3 > len(body):
        raise Uncertain('missing_selected_cipher')
    suite, compression = int.from_bytes(body[offset:offset + 2], 'big'), body[offset + 2]
    return dict(version=version, suite=suite, compression=compression, extensions=extensions(body, offset + 3))


def consecutive_ranges(offsets, kind):
    result = []
    for offset in offsets:
        if result and result[-1][1] == offset:
            result[-1] = (result[-1][0], offset + 1, kind)
        else:
            result.append((offset, offset + 1, kind))
    return result


def tls_ranges(streams):
    parsed = [records(s) for s in streams]
    messages = [handshakes(rs) for rs in parsed]
    clients = [(d, m) for d, ms in enumerate(messages) for m in ms if m['kind'] == 1]
    servers = [(d, m) for d, ms in enumerate(messages) for m in ms if m['kind'] == 2]
    if len(clients) != 1 or len(servers) != 1 or clients[0][0] == servers[0][0]:
        raise Uncertain('missing_ambiguous_or_repeated_hellos')
    client, server = hello(clients[0][1]), hello(servers[0][1])
    if server['suite'] not in client['suites'] or server['compression'] not in client['compressions']:
        raise Uncertain('negotiation_not_offered')
    supported = (client['version'] == server['version'] == 0x0303 and server['compression'] == 0 and
                 server['suite'] in GCM_SUITES and 43 not in server['extensions'])
    ranges, witnesses = [[], []], []
    for direction, record_list in enumerate(parsed):
        active, finished = False, False
        for record in record_list:
            start, end, kind = record['start'], record['end'], record['kind']
            ranges[direction].append((start, start + 5, 'framing'))
            if kind == 20:
                if active or record['body'] != b'\x01':
                    raise Uncertain('invalid_or_repeated_change_cipher_spec')
                active = True
                ranges[direction].append((start + 5, end, 'framing'))
            elif active and supported:
                if record['version'] != 0x0303 or record['length'] < 24:
                    raise Uncertain('invalid_gcm_record')
                if not finished:
                    if kind != 22 or record['length'] != 40:
                        raise Uncertain('missing_expected_protected_finished')
                    finished = True
                elif kind == 22:
                    raise Uncertain('possible_renegotiation')
                elif kind not in (21, 23):
                    raise Uncertain('unexpected_protected_record_type')
                ranges[direction].extend([(start + 5, start + 13, 'framing'),
                                           (start + 13, end - 16, 'ciphertext'),
                                           (end - 16, end, 'authentication')])
                witnesses.append(dict(direction=direction, stream_start=start, stream_end=end,
                    record_type=kind, record_length=record['length'], suite=server['suite'], version=server['version'],
                    ciphertext_stream_range=[start + 13, end - 16],
                    nonce_stream_range=[start + 5, start + 13], tag_stream_range=[end - 16, end]))
            elif active:
                ranges[direction].append((start + 5, end, 'unsupported'))
        # Only fully parsed hello messages are marked plaintext. Other setup
        # messages may contain RSA-encrypted premaster secrets; leave unknown.
        for message in messages[direction]:
            if message['kind'] in (1, 2):
                ranges[direction].extend(consecutive_ranges(message['offsets'], 'plaintext'))
    return dict(protocol='TLS1.2_AES_GCM' if supported else 'TLS_UNSUPPORTED',
                ranges=ranges, records=witnesses, negotiated_suite=server['suite'],
                negotiated_version=server['version'], server_direction=servers[0][0],
                reason='confirmed_negotiation_and_ccs' if supported else 'unsupported_version_cipher_or_compression')


def project(ranges, start, length):
    """Map interpreted stream ranges to exact original packet payload offsets."""
    result = []
    for lo, hi, kind in sorted(ranges):
        a, b = max(start, lo), min(start + length, hi)
        if a < b:
            result.append(dict(start=a - start, end=b - start, kind=kind))
    return result


def classify_flow(flow):
    selected = flow['selected']
    state = dict(protocol='UNKNOWN', reason='unclassified', ranges=[[], []], records=[])
    streams, maps = [], []
    try:
        for direction in (0, 1):
            stream, mapped = reassemble([p for p in selected if p['direction'] == direction], flow['syn'][direction])
            streams.append(stream)
            maps.append(mapped)
        if any(s.startswith(b'SSH-') for s in streams):
            state.update(protocol='SSH_UNSUPPORTED', reason='encrypted_packet_boundaries_and_state_not_established')
            for d, stream in enumerate(streams):
                end = stream.find(b'\r\n')
                if stream.startswith(b'SSH-') and 0 < end < 253:
                    state['ranges'][d] = [(0, end + 2, 'plaintext'), (end + 2, len(stream), 'unsupported')]
        elif any(re.match(rb'(?:HTTP/1\.[01] [1-5][0-9]{2} |(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|TRACE|PATCH) [^\r\n]+ HTTP/1\.[01]\r\n)', s)
                 for s in streams):
            state.update(protocol='HTTP', reason='plaintext_http_start_line; bodies_not_assumed_plaintext')
            for d, stream in enumerate(streams):
                end = stream.find(b'\r\n\r\n')
                if end >= 0 and all(32 <= b < 127 or b in (9, 10, 13) for b in stream[:end + 4]):
                    state['ranges'][d] = [(0, end + 4, 'plaintext')]
        else:
            state = tls_ranges(streams)
    except Uncertain as e:
        state.update(protocol='UNKNOWN', reason=str(e), ranges=[[], []], records=[])
    packets = []
    for p in selected:
        length = min(150, len(p['payload']))
        ranges = []
        if len(flow['syn'][p['direction']]) == 1:
            start = (p['seq'] - next(iter(flow['syn'][p['direction']]))) % 2**32
            ranges = project(state['ranges'][p['direction']], start, length)
        categories = ['unknown'] * length
        for r in ranges:
            if any(x != 'unknown' for x in categories[r['start']:r['end']]):
                raise ValueError('Overlapping protocol range classification')
            categories[r['start']:r['end']] = [r['kind']] * (r['end'] - r['start'])
        counts = {k: categories.count(k) for k in KINDS}
        packets.append(dict(frame=p['frame'], packet_index=p['packet_index'], payload_ordinal=p['payload_ordinal'],
            direction=p['direction'], payload_length=len(p['payload']), retained_payload_bytes=length,
            ranges=ranges, byte_counts=counts, protocol=state['protocol']))
    return {**state, 'packets': packets}
