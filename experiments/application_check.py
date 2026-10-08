"""Bounded independent TShark/Scapy checks of actual TLS record byte offsets."""
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from scapy.layers.inet import IP, TCP

from src.capture import packets
from experiments.application_audit import read
from experiments.capture_audit import ip_offset, save


def check(out):
    OUT = Path(out)
    evidence = read(OUT / 'parser_evidence.json')
    before = read(OUT / 'integrity_before.json')
    by_capture = collections.defaultdict(list)
    for witness in evidence['samples']:
        by_capture[witness['capture']].append(witness)
    checks = []
    for capture, witnesses in sorted(by_capture.items()):
        frames = {p['frame']: p for p in witnesses}
        originals = {}
        path = Path(before['capture_root']) / capture
        for frame, (_, link, raw, _) in enumerate(packets(path), 1):
            if frame not in frames:
                continue
            off = ip_offset(link, raw)
            ip = IP(raw[off:])
            assert TCP in ip and ip.version == 4
            start = off + ip.ihl * 4 + ip[TCP].dataofs * 4
            original = bytes(ip[TCP].payload)
            assert hashlib.sha256(original[:150]).hexdigest() == frames[frame]['retained_payload_sha256']
            originals[frame] = (start, raw)
            if len(originals) == len(frames):
                break
        command = ['tshark', '-n', '-r', str(path), '-o', 'http.desegment_body:FALSE',
                   '-o', 'tls.desegment_ssl_application_data:FALSE',
                   '-Y', ' || '.join(f'frame.number == {frame}' for frame in frames), '-T', 'pdml']
        output = subprocess.run(command, capture_output=True, text=True, check=True)
        tree = ET.fromstring(output.stdout)
        for packet in tree.findall('packet'):
            frame_field = packet.find(".//field[@name='frame.number']")
            frame = int(frame_field.attrib['show'])
            payload_start, raw = originals[frame]
            record_ranges = []
            for record in packet.findall(".//field[@name='tls.record']"):
                kind = record.find(".//field[@name='tls.record.content_type']")
                length = record.find(".//field[@name='tls.record.length']")
                version = record.find(".//field[@name='tls.record.version']")
                if any(v is None for v in (kind, length, version)):
                    continue
                lo, size = int(record.attrib['pos']), int(record.attrib['size'])
                n, typ, ver = (int(v.attrib['value'], 16) for v in (length, kind, version))
                if size != n + 5 or lo < payload_start or lo + size > len(raw) or ver != 0x0303:
                    continue  # Reassembled synthetic offsets are never treated as packet offsets.
                assert raw[lo] == typ and int.from_bytes(raw[lo + 3:lo + 5], 'big') == n
                if typ in (21, 22, 23) and n >= 24:
                    record_ranges.append((lo + 13 - payload_start, lo + size - 16 - payload_start,
                                          lo - payload_start, n, typ))
            corroborated = []
            for r in frames[frame]['classified_ranges']:
                if r['kind'] != 'ciphertext':
                    continue
                for a, b, record_start, n, typ in record_ranges:
                    if a <= r['start'] < r['end'] <= b:
                        corroborated.append(dict(start=r['start'], end=r['end'], record_start=record_start,
                                                 record_length=n, record_type=typ))
                        break
            if corroborated:
                checks.append(dict(source_capture=capture, flow_id=frames[frame]['flow_id'],
                    frame=frame, label=frames[frame]['label'], packet_index=frames[frame]['packet_index'],
                    exact_ciphertext_ranges=corroborated, scapy_payload_matches_cached_hash=True,
                    independent_tshark_record_offsets_match=True))
        print(capture, 'independent bounded checks=', len([c for c in checks if c['source_capture'] == capture]), flush=True)
    assert {c['label'] for c in checks} == {0, 1, 2, 4, 5}, 'Representative protocol checks incomplete'
    assert len(checks) >= 10
    save(OUT / 'independent_parser_checks.json', dict(passed=True, checks=checks, checked_packets=len(checks),
        method='Scapy payload extraction plus TShark PDML complete-record packet offsets; TLS-GCM '
               'suite independently corroborated in coverage audit. Synthetic/reassembled PDML offsets ignored.',
        caveat='Bounded representative check, not cryptographic authentication/decryption. '
               'Cross-segment mapping additionally covered by exact sequence mapping and synthetic tests.',
        ciphertext_transformation_implemented=False))
    print('Independent actual-packet checks passed:', len(checks), flush=True)


if __name__ == '__main__':
    raise SystemExit("Use python -m experiments.tls_prepare --help")
