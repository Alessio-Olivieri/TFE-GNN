"""Read PCAP/PCAPNG without modifying captures; extract SplitCap-style TCP tuples.

IPv4 only for the original fixed-header experiment; all exclusions are counted.
One bidirectional five-tuple per capture is one sample, not 50-packet chunks.
"""
import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import resource
import time

CLASSES = ['Chat', 'Email', 'FileTransfer', 'P2P', 'Streaming', 'VoIP']
SETTINGS = dict(flow_packets=50, header_bytes=40, payload_bytes=150,
                padding_token=256, pmi_window=5, anomalous_data_packets=10000,
                transport='TCP', network='IPv4',
                flow_key='capture + bidirectional TCP five-tuple, no idle timeout',
                header_policy='first 50 TCP headers including ACK-only packets',
                payload_policy='first 50 nonempty TCP payloads, independently padded',
                address_policy='remove IPv4 addresses and TCP ports before truncation',
                fragments='excluded and counted',
                retransmissions='retained, matching tuple extraction')


def checked_read(f, count):
    b = f.read(count)
    if len(b) != count:
        raise ValueError(f'Truncated capture at offset {f.tell()}')
    return b


def options(data, endian):
    i = 0
    while i + 4 <= len(data):
        code, size = struct.unpack_from(endian + 'HH', data, i)
        i += 4
        if code == 0:
            break
        yield code, data[i:i + size]
        i += (size + 3) // 4 * 4


def packets(path):
    """Yield (timestamp, linktype, captured bytes, original length)."""
    with Path(path).open('rb') as f:
        magic = checked_read(f, 4)
        if magic == b'\x0a\x0d\x0d\x0a':
            f.seek(0)
            endian = None
            interfaces = []
            while head := f.read(8):
                if len(head) != 8:
                    raise ValueError('Truncated PCAPNG block header')
                if head[:4] == b'\x0a\x0d\x0d\x0a':
                    bom = checked_read(f, 4)
                    if bom not in (b'\x4d\x3c\x2b\x1a', b'\x1a\x2b\x3c\x4d'):
                        raise ValueError('Invalid PCAPNG byte order')
                    endian = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
                    length = struct.unpack(endian + 'I', head[4:])[0]
                    if length < 28 or length % 4:
                        raise ValueError('Invalid section length')
                    rest = bom + checked_read(f, length - 12)
                    interfaces = []
                else:
                    if endian is None:
                        raise ValueError('Missing PCAPNG section')
                    length = struct.unpack(endian + 'I', head[4:])[0]
                    if length < 12 or length % 4 or length > 32 * 1024 * 1024:
                        raise ValueError('Invalid PCAPNG block length')
                    rest = checked_read(f, length - 8)
                if struct.unpack(endian + 'I', rest[-4:])[0] != length:
                    raise ValueError('PCAPNG block trailer mismatch')
                kind = struct.unpack(endian + 'I', head[:4])[0]
                body = rest[:-4]
                if kind == 1:
                    link, _, snap = struct.unpack_from(endian + 'HHI', body)
                    resolution = 1e-6
                    for code, value in options(body[8:], endian):
                        if code == 9 and value:
                            resolution = (2 if value[0] & 128 else 10) ** -(value[0] & 127)
                    interfaces.append((link, resolution, snap))
                elif kind == 6:
                    iface, hi, lo, cap, orig = struct.unpack_from(endian + 'IIIII', body)
                    link, resolution, _ = interfaces[iface]
                    if cap > len(body) - 20:
                        raise ValueError('Truncated enhanced packet')
                    yield ((hi << 32) | lo) * resolution, link, body[20:20 + cap], orig
                elif kind in (2, 3):
                    raise ValueError('Legacy/simple PCAPNG packets require explicit timestamp handling')
            return
        formats = {b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
                   b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9)}
        if magic not in formats:
            raise ValueError('Unknown capture format')
        endian, resolution = formats[magic]
        header = checked_read(f, 20)
        link = struct.unpack_from(endian + 'I', header, 16)[0]
        while h := f.read(16):
            if len(h) != 16:
                raise ValueError('Truncated PCAP packet header')
            sec, frac, cap, orig = struct.unpack(endian + 'IIII', h)
            if cap > 32 * 1024 * 1024:
                raise ValueError('Invalid captured packet length')
            yield sec + frac * resolution, link, checked_read(f, cap), orig


def tcp_packet(link, data, counts):
    if link == 1:
        if len(data) < 14:
            counts['short_link'] += 1
            return
        ether = int.from_bytes(data[12:14], 'big')
        offset = 14
        while ether in (0x8100, 0x88a8):
            if len(data) < offset + 4:
                counts['short_link'] += 1
                return
            ether = int.from_bytes(data[offset + 2:offset + 4], 'big')
            offset += 4
        if ether != 0x0800:
            counts['non_ipv4'] += 1
            return
    elif link in (101, 228):
        offset = 0
    elif link == 113:
        offset = 16
    else:
        raise ValueError(f'Unsupported link type: {link}')
    ip = data[offset:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        counts['non_ipv4'] += 1
        return
    proto = ip[9]
    if proto != 6:
        counts['UDP' if proto == 17 else 'other_ip'] += 1
        return
    counts['TCP'] += 1
    if int.from_bytes(ip[6:8], 'big') & 0x3fff:
        counts['tcp_fragments_excluded'] += 1
        return
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    if ihl < 20 or total < ihl + 20 or len(ip) < total:
        counts['malformed_or_truncated_tcp'] += 1
        return
    tcp = ip[ihl:total]
    thl = (tcp[12] >> 4) * 4
    if thl < 20 or len(tcp) < thl:
        counts['malformed_or_truncated_tcp'] += 1
        return
    a = ip[12:16] + tcp[:2]
    b = ip[16:20] + tcp[2:4]
    pair = tuple(sorted((a, b)))
    # Preserve IP options; remove ports at the actual IHL, not fixed offset 20.
    header = ip[:12] + ip[20:ihl] + tcp[4:thl]
    return pair, int(a != pair[0]), list(header[:40]), tcp[thl:], total


def audit(root):
    captures, samples = [], []
    for label, category in enumerate(CLASSES):
        paths = sorted((root / category).glob('*.pcap'))
        if not paths:
            raise ValueError(f'No captures in {root / category}')
        for path in paths:
            rel = str(path.relative_to(root))
            counts = collections.Counter()
            flows = {}
            links = set()
            for timestamp, link, data, orig in packets(path):
                counts['packets'] += 1
                links.add(link)
                if len(data) < orig:
                    counts['snaplen_shortened_packets'] += 1
                record = tcp_packet(link, data, counts)
                if record is None:
                    continue
                key, direction, header, payload, packet_length = record
                flow = flows.setdefault(key, dict(headers=[], payloads=[], payload_lengths=[],
                                                 packet_lengths=[], directions=[0, 0],
                                                 data_packets=0, first=timestamp, last=timestamp))
                flow['last'] = timestamp
                flow['directions'][direction] += 1
                if len(flow['headers']) < 50:
                    flow['headers'].append(header)
                    flow['packet_lengths'].append(packet_length)
                if payload:
                    counts['tcp_data_packets'] += 1
                    flow['data_packets'] += 1
                    if len(flow['payloads']) < 50:
                        flow['payloads'].append(list(payload[:150]))
                        flow['payload_lengths'].append(len(payload))
            with path.open('rb') as f:
                sha = hashlib.file_digest(f, 'sha256').hexdigest()
                f.seek(0)
                capture_format = 'pcapng' if f.read(4) == b'\x0a\x0d\x0d\x0a' else 'pcap'
            excluded = collections.Counter()
            kept = 0
            for key, flow in flows.items():
                if not flow['data_packets']:
                    excluded['empty_payload_flow'] += 1
                    continue
                if flow['data_packets'] > 10000:
                    excluded['anomalous_flow'] += 1
                    continue
                tuple_hash = hashlib.sha256(b''.join(key)).hexdigest()
                sample_id = hashlib.sha256((sha + tuple_hash).encode()).hexdigest()
                content_hash = hashlib.sha256(json.dumps(
                    [flow['headers'], flow['payloads'], flow['payload_lengths']],
                    separators=(',', ':')).encode()).hexdigest()
                samples.append(dict(id=sample_id, label=label, capture=rel,
                                    source_family=category + '/' + re.sub(r'(?i)[_-]?[ab]$', '', path.stem),
                                    tuple_hash=tuple_hash, content_hash=content_hash, **flow))
                kept += 1
            entry = dict(path=rel, sha256=sha, bytes=path.stat().st_size,
                         format=capture_format,
                         link_types=sorted(links), counts=dict(counts), tcp_tuples=len(flows),
                         bidirectional_tuples=sum(all(f['directions']) for f in flows.values()),
                         eligible_samples=kept, excluded_flows=dict(excluded))
            captures.append(entry)
            print(f'{rel}: {counts["packets"]} packets; {len(flows)} TCP tuples; {kept} eligible flows', flush=True)
    # Stable ordering is independent of dictionary traversal and condition.
    samples.sort(key=lambda s: (s['label'], s['capture'], s['id']))
    summary = dict(classes=CLASSES, settings=SETTINGS, captures=captures,
                   sample_counts={c: sum(s['label'] == i for s in samples) for i, c in enumerate(CLASSES)},
                   total_samples=len(samples),
                   duplicate_representation_groups=sum(n > 1 for n in collections.Counter(
                       s['content_hash'] for s in samples).values()),
                   capture_isolation_feasible=all(sum(p['path'].startswith(c + '/') for p in captures) >= 3 for c in CLASSES))
    return summary, samples


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data-root', type=Path, default=Path('../ICSX-VPN'))
    p.add_argument('--output', type=Path, default=Path('data/recovery'))
    args = p.parse_args()
    if args.output.exists():
        raise SystemExit(f'Refusing to overwrite existing output: {args.output}')
    started = time.monotonic()
    summary, samples = audit(args.data_root.resolve())
    summary['resources'] = dict(elapsed_seconds=time.monotonic() - started,
                                peak_process_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
                                gpu_used=False)
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'audit.json').write_text(json.dumps(summary, indent=2) + '\n')
    with gzip.open(args.output / 'flows.json.gz', 'xt') as f:
        json.dump(samples, f, separators=(',', ':'))
    print(json.dumps({k: v for k, v in summary.items() if k != 'captures'}, indent=2))


if __name__ == '__main__':
    main()
