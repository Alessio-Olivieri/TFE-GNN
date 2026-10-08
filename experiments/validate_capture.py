"""Cross-check custom extraction against independent Scapy capture reading."""
import argparse
import collections
import json
from pathlib import Path

from scapy.all import Ether, IP, TCP, RawPcapReader, raw

from src.capture import tcp_packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-root', type=Path, required=True)
    parser.add_argument('--data', type=Path, default=Path('data/recovery'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    audit = json.loads((args.data / 'audit.json').read_text())
    checks = []
    for capture in audit['captures']:
        path = args.capture_root / capture['path']
        count = compared = 0
        with RawPcapReader(str(path)) as reader:
            for data, meta in reader:
                count += 1
                if compared >= 50:
                    continue
                link = getattr(meta, 'linktype', getattr(reader, 'linktype', None))
                record = tcp_packet(link, data, collections.Counter())
                if record is None:
                    continue
                pkt = Ether(data) if link == 1 else IP(data)
                ip, tcp = pkt[IP], pkt[TCP]
                payload = raw(tcp.payload)
                expected = raw(ip)[:ip.ihl * 4] + raw(tcp)[:tcp.dataofs * 4]
                expected = expected[:12] + expected[20:ip.ihl * 4] + expected[ip.ihl * 4 + 4:]
                assert record[2] == list(expected[:40]), (path, count, 'header mismatch')
                assert record[3] == payload, (path, count, 'payload mismatch')
                compared += 1
        assert count == capture['counts']['packets'], (path, count, capture['counts']['packets'])
        checks.append(dict(path=capture['path'], scapy_packets=count, tcp_packets_compared=compared))
        print(path.name, count, compared, 'OK', flush=True)
    report = dict(backend='Scapy RawPcapReader + IP/TCP dissection', captures=checks,
                  total_packets=sum(c['scapy_packets'] for c in checks),
                  compared_tcp_packets=sum(c['tcp_packets_compared'] for c in checks), passed=True)
    with args.output.open('x') as f:
        json.dump(report, f, indent=2)


if __name__ == '__main__':
    main()
