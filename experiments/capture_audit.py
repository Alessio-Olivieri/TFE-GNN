"""Read-only acquisition feasibility and quantitative capture-layer audit.

Uses exact packet extraction without changing source captures or model inputs.
"""
import argparse
import collections
import copy
import csv
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from src.capture import CLASSES, packets, tcp_packet, options
from src.resources import ResourceMonitor

VERSION = 'capture-audit-v1'
OUT = Path('results/capture_disjoint')
CIPHER_OUT = Path('results/ciphertext_randomized')
SOURCES = {
    'dataset': 'https://www.unb.ca/cic/datasets/vpn.html',
    'upstream': 'https://github.com/ViktorAxelsen/TFE-GNN',
    'tls12': 'https://www.rfc-editor.org/rfc/rfc5246',
    'gcm': 'https://www.rfc-editor.org/rfc/rfc5288',
    'ecdhe_gcm': 'https://www.rfc-editor.org/rfc/rfc5289',
    'ssh': 'https://www.rfc-editor.org/rfc/rfc4253',
}


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def save(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def csv_save(path, rows):
    with Path(path).open('x', newline='') as f:
        columns = list(dict.fromkeys(k for row in rows for k in row))
        writer = csv.DictWriter(f, fieldnames=columns, lineterminator='\n')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v
                             for k, v in row.items()})


def load_samples():
    with gzip.open('data/recovery/flows.json.gz', 'rt') as f:
        return json.load(f)


def acquisition_key(path):
    """Conservative candidate groups, NEVER a certificate of independence.

    A/B activity pairs share overlapping or closely spaced intervals. Audio
    1/2 pairs below overlap for almost the entire call. Distinct groups remain
    unverified because no acquisition/interface log was supplied.
    """
    p = Path(path)
    stem = re.sub(r'(?i)[_-]?[ab]$', '', p.stem)
    if p.parent.name == 'VoIP' and stem in ('vpn_hangouts_audio1', 'vpn_hangouts_audio2',
                                           'vpn_skype_audio1', 'vpn_skype_audio2'):
        stem = stem[:-1]
    return f'{p.parent.name}/{stem}'


def assess_feasibility(inventory):
    groups = {c: sorted({r['capture_group_id'] for r in inventory
                        if r['sample_counts'].get(c, 0) > 0}) for c in CLASSES}
    limiting = {c: g for c, g in groups.items() if len(g) < 2}
    if limiting:
        protocol = 'STOP'
        reason = 'Fewer than two candidate acquisition groups for: ' + ', '.join(limiting)
    elif any(len(g) < 3 for g in groups.values()):
        protocol = 'candidate_grouped_cv'
        reason = 'At least two but fewer than three candidate groups per class; independence must be verified first.'
    else:
        protocol = 'candidate_three_way'
        reason = 'Candidate group counts suffice; independence and actual allocation must still be verified.'
    return dict(protocol=protocol, reason=reason, groups_by_class=groups,
                group_counts={c: len(g) for c, g in groups.items()}, blocking_classes=limiting,
                genuine_independence_certified=False, split_seed=32,
                training_permitted=False, split_or_fold_manifest_created=False)


def refine_capture_groups(inventory, samples):
    """Join activity groups linked by canonical tuples or identical input bytes.

    Endpoint reuse is not proof of one acquisition, but conservatively prevents
    treating persistent/reused connections as evidence of independence. The
    result is still an upper bound, NEVER an independence certificate.
    """
    initial = {c['source_pcap']: c['capture_group_id'] for c in inventory}
    parent = {g: g for g in initial.values()}

    def find(g):
        while parent[g] != g:
            parent[g] = parent[parent[g]]
            g = parent[g]
        return g

    def union(a, b):
        a, b = sorted((find(a), find(b)))
        parent[b] = a

    evidence = []
    for key in ('tuple_hash', 'content_hash'):
        matches = collections.defaultdict(list)
        for s in samples:
            matches[s[key]].append(s)
        for digest, records in sorted(matches.items()):
            captures = sorted({r['capture'] for r in records})
            if len(captures) < 2:
                continue
            for capture in captures[1:]:
                union(initial[captures[0]], initial[capture])
            evidence.append(dict(evidence_key=key, digest=digest, source_captures=captures,
                source_sample_ids=sorted(r['id'] for r in records),
                source_flow_intervals=[dict(capture=r['capture'], first=r.get('first'), last=r.get('last'))
                                       for r in sorted(records, key=lambda r: r['id'])],
                interpretation='Conservative related-flow link, not proof of identical acquisition. '
                               'TCP tuple reuse may be persistent connections or port reuse.'))
    members = collections.defaultdict(list)
    for capture, group in initial.items():
        members[find(group)].append(capture)
    refined = copy.deepcopy(inventory)
    for c in refined:
        sources = sorted(members[find(c['capture_group_id'])])
        families = {initial[s] for s in sources}
        c['initial_activity_group_id'] = c['capture_group_id']
        if len(families) > 1:
            fingerprint = hashlib.sha256(json.dumps(sources, separators=(',', ':')).encode()).hexdigest()[:12]
            labels = sorted({s.split('/')[0] for s in sources})
            c['capture_group_id'] = '+'.join(labels) + '/linked-' + fingerprint
            c['group_reason'] = ('Related activity groups linked transitively by shared canonical TCP endpoint tuples '
                                 'or identical model input. Conservatively keep together; endpoint reuse does not prove independence.')
        c['grouping_version'] = 'capture-audit-v2-conservative-session-links'
    return refined, evidence


def validate_assignment(records, assignment, samples):
    """Reject missing/extra samples, altered labels, and acquisition overlap.

    Assignment is sample ID -> partition; use separately for each CV fold.
    """
    expected = {s['id']: s for s in samples}
    if len(records) != len(expected) or {r['id'] for r in records} != set(expected):
        raise ValueError('Each source sample must have exactly one provenance record')
    if set(assignment) != set(expected):
        raise ValueError('Every sample must have exactly one partition')
    locations = collections.defaultdict(set)
    for r in records:
        s = expected[r['id']]
        if r['label'] != s['label'] or r['capture'] != s['capture']:
            raise ValueError('Source identity or class label changed')
        locations[r['capture_group_id']].add(assignment[r['id']])
    if any(len(v) != 1 for v in locations.values()):
        raise ValueError('Capture-group overlap between partitions')
    return True


def ip_offset(link, raw):
    if link == 1:
        if len(raw) < 14:
            return None
        off, kind = 14, int.from_bytes(raw[12:14], 'big')
        while kind in (0x8100, 0x88a8):
            if len(raw) < off + 4:
                return None
            kind, off = int.from_bytes(raw[off + 2:off + 4], 'big'), off + 4
        return off if kind == 0x0800 else None
    return 0 if link in (101, 228) else 16 if link == 113 else None


def capture_metadata(path):
    with Path(path).open('rb') as f:
        if f.read(4) != b'\x0a\x0d\x0d\x0a':
            return dict(format='pcap', interface_name=None, acquisition_location='UNKNOWN')
        f.seek(0)
        found = []
        for _ in range(8):
            head = f.read(8)
            if len(head) < 8:
                break
            # The local PCAPNG is little endian; never guess for other files.
            if head[:4] == b'\x0a\x0d\x0d\x0a':
                bom = f.read(4)
                endian = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
                size = struct.unpack(endian + 'I', head[4:])[0]
                body = bom + f.read(size - 12)
                offset = 16
            else:
                size = struct.unpack(endian + 'I', head[4:])[0]
                body = f.read(size - 8)
                offset = 8
            kind = struct.unpack(endian + 'I', head[:4])[0]
            if kind in (1, 0x0a0d0d0a):
                found.extend(dict(block=kind, code=code, value=value.decode('utf8', errors='replace'))
                             for code, value in options(body[offset:-4], endian) if code != 9)
        return dict(format='pcapng', options=found, interface_name=None, acquisition_location='UNKNOWN')


def scan_capture(path, capture, samples):
    """Trace actual raw packets to the exact cached model input, in RAM only."""
    expected = {s['tuple_hash']: s for s in samples if s['capture'] == capture}
    counts = collections.Counter()
    flows, modeled, witnesses = {}, {}, []
    first, last = float('inf'), -float('inf')
    for frame, (timestamp, link, raw, original_length) in enumerate(packets(path), 1):
        first, last = min(first, timestamp), max(last, timestamp)
        counts['raw_packets'] += 1
        counts['raw_captured_bytes'] += len(raw)
        off = ip_offset(link, raw)
        if off is not None and len(raw) >= off + 20 and raw[off] >> 4 == 4:
            proto = raw[off + 9]
            counts['raw_tcp_packets' if proto == 6 else 'raw_udp_packets' if proto == 17 else 'raw_other_ipv4_packets'] += 1
        else:
            counts['raw_non_ipv4_packets'] += 1
        record = tcp_packet(link, raw, collections.Counter())
        if record is None:
            continue
        pair, direction, header, payload, ip_length = record
        flow = flows.get(pair)
        if flow is None:
            digest = hashlib.sha256(b''.join(pair)).hexdigest()
            sample = expected.get(digest)
            flow = flows[pair] = dict(sample=sample, packets=0, data_packets=0,
                ip_bytes=0, payload_bytes=0, headers=[], payloads=[],
                syn=[set(), set()], selected=[])
        ip = raw[off:]
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl:]
        seq = int.from_bytes(tcp[4:8], 'big')
        if tcp[13] & 2:
            flow['syn'][direction].add((seq + 1) % 2**32)
        flow['packets'] += 1
        flow['ip_bytes'] += ip_length
        counts['valid_tcp_packets'] += 1
        counts['valid_tcp_ip_bytes'] += ip_length
        counts['raw_valid_tcp_payload_bytes'] += len(payload)
        sample = flow['sample']
        selected_header = sample is not None and len(flow['headers']) < 50
        if selected_header:
            flow['headers'].append(header)
        selected_payload = bool(sample is not None and payload and len(flow['payloads']) < 50)
        if payload:
            flow['data_packets'] += 1
            flow['payload_bytes'] += len(payload)
            counts['valid_tcp_payload_packets'] += 1
        if selected_payload:
            flow['payloads'].append(list(payload[:150]))
            packet = dict(frame=frame, packet_index=flow['packets'] - 1,
                payload_ordinal=len(flow['payloads']) - 1, direction=direction, seq=seq,
                payload=payload, sample_id=sample['id'])
            flow['selected'].append(packet)
            counts['model_payload_packets'] += 1
            counts['selected_full_payload_bytes'] += len(payload)
            counts['model_real_payload_bytes'] += min(len(payload), 150)
        if selected_header:
            counts['model_header_packets'] += 1
            counts['model_real_header_bytes'] += len(header)
        if selected_header or selected_payload:
            modeled[frame] = dict(sample_id=sample['id'], header=selected_header, payload=selected_payload)
    eligible = [f for f in flows.values() if f['sample'] is not None]
    if len(eligible) != len(expected):
        raise ValueError('Raw flow identities differ from cached dataset')
    for f in eligible:
        s = f['sample']
        if f['headers'] != s['headers'] or f['payloads'] != s['payloads']:
            raise ValueError(f'Raw extraction differs from cached model bytes: {s["id"]}')
        if [len(p['payload']) for p in f['selected']] != s['payload_lengths']:
            raise ValueError('Original payload lengths differ')
        counts['eligible_flow_tcp_packets'] += f['packets']
        counts['eligible_flow_ip_bytes'] += f['ip_bytes']
    counts['all_bidirectional_tcp_tuples'] = len(flows)
    counts['usable_samples'] = len(eligible)
    counts['model_unique_source_packets'] = len(modeled)
    counts['model_payload_slots_with_padding'] = 50 * len(eligible)
    counts['model_payload_tokens_with_padding'] = 50 * 150 * len(eligible)
    counts['model_header_tokens_with_padding'] = 50 * 40 * len(eligible)
    return dict(counts=dict(counts), first=first, last=last), modeled, eligible


def dissector(path, tshark, modeled):
    fields = ['frame.number', 'frame.protocols', 'tls.handshake.type', 'tls.handshake.version',
              'tls.handshake.ciphersuite', 'tls.handshake.comp_method']
    command = [tshark, '-n', '-r', str(path), '-o', 'http.desegment_body:FALSE',
               '-o', 'tls.desegment_ssl_application_data:FALSE', '-T', 'fields']
    for field in fields:
        command += ['-e', field]
    raw_counts, model_counts, hellos = collections.Counter(), collections.Counter(), []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            values = line.rstrip('\n').split('\t')
            values += [''] * (len(fields) - len(values))
            frame = int(values[0])
            labels = set(values[1].split(':')) - {''}
            raw_counts.update(labels)
            if frame in modeled:
                model_counts.update(labels)
            if '2' in values[2].split(','):
                hellos.append(dict(frame=frame, version=values[3], cipher_suite=values[4],
                    compression=values[5], sample_id=modeled.get(frame, {}).get('sample_id')))
        errors = process.stderr.read()
        if process.wait():
            raise RuntimeError(errors)
    return dict(command=command, raw_packet_protocol_labels=dict(raw_counts),
                model_source_packet_protocol_labels=dict(model_counts), server_hellos=hellos,
                caveat='Dissector labels are observations, not ground truth. Heuristic/malformed matches are not ciphertext certification.')


