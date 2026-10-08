"""Publish feasibility STOP reports without inventing splits or ciphertext coverage.

Transport, timestamp and protocol-coverage evidence helpers.
"""
import collections
import csv
import datetime
import importlib.metadata
import itertools
import json
from pathlib import Path
import subprocess
import sys

from src.capture import CLASSES, packets
from experiments.capture_audit import (OUT, CIPHER_OUT, SOURCES, csv_save, save, load_samples,
                                    refine_capture_groups, assess_feasibility, sha)


def read(path):
    return json.loads(Path(path).read_text())


def text_save(path, text):
    with Path(path).open('x') as handle:
        handle.write(text.rstrip() + '\n')


def table(columns, rows):
    return '\n'.join(['| ' + ' | '.join(columns) + ' |',
                      '| ' + ' | '.join(['---'] * len(columns)) + ' |',
                      *['| ' + ' | '.join(map(str, row)) + ' |' for row in rows]])


def ipv6_transport(data):
    """Only for counting excluded IPv6 traffic; never used for model extraction."""
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    nxt, off = data[6], 40
    for _ in range(16):
        if nxt not in (0, 43, 44, 51, 60):
            return nxt
        if off + 8 > len(data):
            return None
        if nxt == 44:
            # Non-initial fragments cannot establish transport packet structure.
            if int.from_bytes(data[off + 2:off + 4], 'big') & 0xfff8:
                return None
            size = 8
        else:
            size = (data[off + 1] + (2 if nxt == 51 else 1)) * (4 if nxt == 51 else 8)
        nxt, off = data[off], off + size
    return None


def supplemental_scope(captures, capture_root):
    """Disambiguate outer IPv6 and OpenVPN labels inside ICMP quotations."""
    rows, observations = [], []
    for c in captures:
        counts = c['stage_counts']
        ipv6 = collections.Counter()
        if c['protocol_dissector']['raw_packet_protocol_labels'].get('ipv6', 0):
            for _, link, raw, _ in packets(Path(capture_root) / c['source_pcap']):
                if link != 1 or len(raw) < 54 or raw[12:14] != b'\x86\xdd':
                    continue
                proto = ipv6_transport(raw[14:])
                ipv6['packets'] += 1
                ipv6['tcp' if proto == 6 else 'udp' if proto == 17 else 'other'] += 1
        row = dict(source_capture=c['source_pcap'], class_label=c['labels'][0],
                   raw_packets=counts['raw_packets'], raw_ipv4_tcp_packets=counts.get('raw_tcp_packets', 0),
                   raw_ipv4_udp_packets=counts.get('raw_udp_packets', 0),
                   raw_ipv6_tcp_packets=ipv6['tcp'], raw_ipv6_udp_packets=ipv6['udp'],
                   raw_ipv6_other_packets=ipv6['other'], raw_ipv6_packets=ipv6['packets'])
        row['raw_outer_tcp_packets'] = row['raw_ipv4_tcp_packets'] + row['raw_ipv6_tcp_packets']
        row['raw_outer_udp_packets'] = row['raw_ipv4_udp_packets'] + row['raw_ipv6_udp_packets']
        row['raw_outer_other_packets'] = row['raw_packets'] - row['raw_outer_tcp_packets'] - row['raw_outer_udp_packets']
        row['raw_outer_tcp_percent'] = 100 * row['raw_outer_tcp_packets'] / row['raw_packets']
        row['raw_outer_udp_percent'] = 100 * row['raw_outer_udp_packets'] / row['raw_packets']
        rows.append(row)
        if c['protocol_dissector']['raw_packet_protocol_labels'].get('openvpn', 0):
            command = ['tshark', '-n', '-r', str(Path(capture_root) / c['source_pcap']),
                       '-Y', 'openvpn', '-T', 'fields']
            fields = ['frame.number', 'frame.len', 'frame.protocols', 'ip.proto',
                      'udp.length', 'openvpn.opcode', 'openvpn.keyid', '_ws.expert.message']
            for field in fields:
                command += ['-e', field]
            result = subprocess.run(command, text=True, capture_output=True, check=True)
            for line in result.stdout.splitlines():
                values = line.split('\t')
                values += [''] * (len(fields) - len(values))
                record = dict(zip(fields, values))
                record['source_capture'] = c['source_pcap']
                record['inside_icmp_quote'] = ':icmp:ip:udp:openvpn' in record['frame.protocols']
                record['survives_model_filter'] = False if record['inside_icmp_quote'] else None
                observations.append(record)
    return dict(scope='Outer on-wire transport; IPv4 model filter excludes IPv6, ICMP and all UDP. '
                      'TShark protocol-label counts can include protocols nested in ICMP quotations and are not outer L4 counts.',
                captures=rows, openvpn_label_observations=observations,
                confirmed_outer_openvpn_packets=None,
                outer_openvpn_labels=len([r for r in observations if not r['inside_icmp_quote']]),
                openvpn_absence_proven=False)


def group_evidence(captures):
    result = []
    for group in sorted({c['capture_group_id'] for c in captures}):
        members = [c for c in captures if c['capture_group_id'] == group]
        relationships = []
        for a, b in itertools.combinations(members, 2):
            overlap = min(a['last_timestamp'], b['last_timestamp']) - max(a['first_timestamp'], b['first_timestamp'])
            relationships.append(dict(a=a['source_pcap'], b=b['source_pcap'],
                                      overlap_seconds=max(0, overlap), gap_seconds=max(0, -overlap)))
        result.append(dict(capture_group_id=group, members=[c['source_pcap'] for c in members],
                           usable_samples=sum(c['usable_samples'] for c in members), relationships=relationships,
                           evidence=members[0]['group_reason'],
                           independent_of_other_groups='UNVERIFIED',
                           permitted_to_subdivide=False))
    return result


def coverage_status(captures):
    """NULL means not assessed, never zero ciphertext or zero unknown bytes."""
    rows = []
    for scope, ids in [('capture', [c['source_pcap'] for c in captures]), ('class', CLASSES),
                       ('capture_group', sorted({c['capture_group_id'] for c in captures}))]:
        for key in ids:
            selected = [c for c in captures if (c['source_pcap'] if scope == 'capture' else
                        c['labels'][0] if scope == 'class' else c['capture_group_id']) == key]
            counts = collections.Counter()
            for c in selected:
                counts.update(c['stage_counts'])
            rows.append(dict(scope=scope, id=key, captures=len(selected), usable_flows=counts['usable_samples'],
                raw_packets=counts['raw_packets'], model_unique_source_packets=counts['model_unique_source_packets'],
                model_payload_packets=counts['model_payload_packets'], model_payload_bytes=counts['model_real_payload_bytes'],
                packets_with_confirmed_ciphertext=None, packets_without_ciphertext=None,
                packets_with_unsupported_structure=None, framing_bytes=None, plaintext_bytes=None,
                confirmed_ciphertext_bytes=None, authentication_bytes=None, padding_bytes=None, unknown_bytes=None,
                ciphertext_percent=None, unknown_percent=None, unassessed_bytes=counts['model_real_payload_bytes'],
                status='NOT_ASSESSED_AFTER_EVALUATION_STOP'))
    protocol_rows = []
    for protocol in ('tls', 'ssh', 'http', 'ftp', 'stun', 'data'):
        count = sum(c['protocol_dissector']['model_source_packet_protocol_labels'].get(protocol, 0) for c in captures)
        protocol_rows.append(dict(protocol_label=protocol, model_source_packets_with_label=count,
                                  confirmed_ciphertext_bytes=None, coverage_status='NOT_ASSESSED',
                                  caveat='Labels overlap and include handshake/framing packets; not ciphertext coverage.'))
    return dict(status='STOP_NO_CAPTURE_INDEPENDENT_PROTOCOL',
                range_parser_executed=False, randomization_executed=False, representation_rebuilt=False,
                reason='Experiment 1 cannot supply the mandatory capture-independent evaluation protocol. '
                       'Per the phase order, ciphertext range parsing and transformation are not implemented after this STOP.',
                units='Model payload bytes are the first <=150 bytes of first <=50 nonempty TCP payloads per usable flow; padding excluded.',
                null_semantics='Unassessed, not zero. Do not infer that all bytes are ciphertext, plaintext, or unknown.',
                total_captures=len(captures), total_flows=sum(c['usable_samples'] for c in captures),
                total_model_payload_packets=sum(c['stage_counts']['model_payload_packets'] for c in captures),
                total_model_payload_bytes=sum(c['stage_counts']['model_real_payload_bytes'] for c in captures),
                by_scope=rows, protocol_observations=protocol_rows,
                future_protocol_candidates=['TLS 1.2 AES-GCM after complete handshake, negotiated-suite and ChangeCipherSpec validation'],
                insufficient_evidence=['Dissector label or TLS record prefix alone', 'Filename, label or TCP/UDP port',
                                       'CBC encrypted MAC/padding boundaries without keys', 'Unreassembled or midstream TLS/SSH'],
                proposed_ciphertext_seed=32, seed_applied=False, transformation_version=None)


