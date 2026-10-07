# Ciphertext-only randomization: STOP after capture-layer audit

Experiment 2 cannot use its mandatory evaluation boundary: Experiment 1 has no valid six-class capture-independent split or CV. No ciphertext-only parser, mutation, rebuilt graph cache, pilot, model training or classification result was produced. This report documents the completed read-only layer audit and what remains unassessed. It does not claim ciphertext absence or insufficient byte coverage; the decisive STOP is missing independent evaluation sources.

## Capture point and retained layer

The [ISCXVPN2016 documentation](https://www.unb.ca/cic/datasets/vpn.html) describes OpenVPN in UDP mode. Actual supplied captures contain mixed traffic. The adapted TFE-GNN runner retains only valid unfragmented IPv4/TCP packets. It cannot retain the documented outer UDP OpenVPN datagrams. Packet structure exposes ordinary application TLS handshakes, HTTP messages and SSH, rather than uniformly VPN tunnel ciphertext. This is application TCP traffic; whether observed before VPN encryption, after VPN decryption or on a particular interface remains UNKNOWN. Raw-IP link type alone does not resolve that location. Some unknown TCP payloads remain uninterpreted; they are not declared encrypted solely by label or filename.

There are 29 raw-IP captures and two Ethernet VoIP captures. `vpn_hangouts_audio2.pcap` is actually PCAPNG; its metadata identifies Editcap 1.12.3, with no supplied interface name/location. The two Ethernet captures also contain 1,540 excluded IPv6 frames. Original stage JSON counts `raw_tcp_packets`/`raw_udp_packets` refer to outer IPv4. `transport_scope_audit.json` adds outer IPv6 transport counts and unambiguous all-network totals; protocol dissector counters can include nested ICMP quotations and should not replace outer L4 counts.

TShark labelled six packets as OpenVPN, all in `vpn_voipbuster1b.pcap`, frames 177433–177438. Their actual stack is `eth:ethertype:ip:icmp:ip:udp:openvpn`: quoted datagrams in ICMP errors, not retained TCP packets. No direct outer OpenVPN dissection label occurred. This does not prove OpenVPN is absent on arbitrary ports, or certify unknown UDP data. Confirmed outer OpenVPN counts remain null. All six quoted matches are excluded from model inputs; model OpenVPN labels are zero.

## Quantitative stage trace

| Class | Raw packets | Outer TCP | Outer UDP | Packets in eligible TCP flows | Nonempty payload packets reaching model | Real model payload bytes |
| --- | --- | --- | --- | --- | --- | --- |
| Chat | 86,226 | 78,279 (90.78%) | 7,838 (9.09%) | 78,179 | 3,874 | 375,064 |
| Email | 21,581 | 21,248 (98.46%) | 310 (1.44%) | 21,205 | 2,839 | 234,755 |
| FileTransfer | 378,089 | 359,287 (95.03%) | 17,416 (4.61%) | 166,676 | 9,884 | 1,013,654 |
| P2P | 422,098 | 415,329 (98.40%) | 6,745 (1.60%) | 415,327 | 9,668 | 1,446,055 |
| Streaming | 1,514,288 | 1,511,466 (99.81%) | 2,725 (0.18%) | 152,585 | 4,282 | 555,434 |
| VoIP | 2,413,699 | 113,801 (4.71%) | 2,298,136 (95.21%) | 113,324 | 10,415 | 1,041,415 |

Across all files: 4,835,981 raw packets; 2,499,410 outer TCP; 2,333,170 outer UDP. All 2,499,410 valid IPv4/TCP packets survive the network/transport filter, before flow exclusions. There are 1,902 logical bidirectional TCP tuples, 1,674 eligible flows, and 947,296 packets in those flows. The exact model uses 57,450 header packets and 40,962 nonempty payload packets, whose union is 69,321 source packets; header/payload selection is independent, so do not add these counts.

Selected full payloads contain 28,021,099 bytes. The 150-byte cap leaves 4,666,377 real payload bytes; sanitized/truncated headers contain 2,257,256 bytes. Padding expands payload input to 12,555,000 tokens and header input to 3,348,000 tokens; token 256 is not a captured byte. Full stage packet counts and percentages plus byte counts/percentages for every capture are in `capture_layer_audit_effective.json` / `.csv`; all-network outer-L4 percentages are in `transport_scope_audit.csv`. Per-class stage percentages are in `stage_summary.csv`. The original `capture_layer_audit.json` / `.csv` is retained as intermediate evidence using the initial 18 activity groups; final effective group IDs are in the `_effective` files, consistent with the final provenance inventory and coverage denominators.

Actual path: raw PCAP/PCAPNG → in-memory canonical bidirectional TCP tuple grouping → `data/recovery/flows.json.gz` → capped/padded header and payload sequences → packet-local PMI byte graphs → PyG model. There is no executed SplitCap, per-flow PCAP or NPZ stage in this adapted runner; generated SplitCap flow counts and actual NPZ packet/byte counts are null, not fabricated. Source-packet indices and exact cached byte sequences were re-extracted and checked across every usable flow. No original payload bytes were printed or saved in new audit outputs.

## Protocol observations per capture

| Source | Candidate group | Model source packets: TLS / HTTP / SSH | Acquisition location |
| --- | --- | --- | --- |
| Chat/vpn_aim_chat1a.pcap | Chat/linked-c257653d273a | 62 / 0 / 0 | UNKNOWN |
| Chat/vpn_aim_chat1b.pcap | Chat/linked-c257653d273a | 126 / 0 / 0 | UNKNOWN |
| Chat/vpn_facebook_chat1a.pcap | Chat/linked-c257653d273a | 421 / 10 / 0 | UNKNOWN |
| Chat/vpn_facebook_chat1b.pcap | Chat/linked-c257653d273a | 85 / 0 / 0 | UNKNOWN |
| Chat/vpn_hangouts_chat1a.pcap | Chat/linked-c257653d273a | 1165 / 20 / 0 | UNKNOWN |
| Chat/vpn_hangouts_chat1b.pcap | Chat/linked-c257653d273a | 673 / 0 / 0 | UNKNOWN |
| Chat/vpn_icq_chat1a.pcap | Chat/linked-c257653d273a | 72 / 0 / 0 | UNKNOWN |
| Chat/vpn_icq_chat1b.pcap | Chat/linked-c257653d273a | 49 / 0 / 0 | UNKNOWN |
| Chat/vpn_skype_chat1a.pcap | Chat/linked-c257653d273a | 59 / 0 / 0 | UNKNOWN |
| Chat/vpn_skype_chat1b.pcap | Chat/linked-c257653d273a | 50 / 0 / 0 | UNKNOWN |
| Email/vpn_email2a.pcap | Email/vpn_email2 | 1177 / 12 / 0 | UNKNOWN |
| Email/vpn_email2b.pcap | Email/vpn_email2 | 1569 / 12 / 0 | UNKNOWN |
| FileTransfer/vpn_ftps_A.pcap | FileTransfer/vpn_ftps | 761 / 0 / 0 | UNKNOWN |
| FileTransfer/vpn_ftps_B.pcap | FileTransfer/vpn_ftps | 552 / 0 / 0 | UNKNOWN |
| FileTransfer/vpn_sftp_A.pcap | FileTransfer/vpn_sftp | 73 / 0 / 77 | UNKNOWN |
| FileTransfer/vpn_sftp_B.pcap | FileTransfer/vpn_sftp | 12 / 0 / 94 | UNKNOWN |
| FileTransfer/vpn_skype_files1a.pcap | FileTransfer/vpn_skype_files1 | 58 / 0 / 0 | UNKNOWN |
| FileTransfer/vpn_skype_files1b.pcap | FileTransfer/vpn_skype_files1 | 438 / 15 / 0 | UNKNOWN |
| P2P/vpn_bittorrent.pcap | P2P/vpn_bittorrent | 108 / 9311 / 0 | UNKNOWN |
| Streaming/vpn_netflix_A.pcap | Streaming/linked-344af536ded1 | 347 / 390 / 0 | UNKNOWN |
| Streaming/vpn_spotify_A.pcap | Streaming/linked-344af536ded1 | 421 / 120 / 0 | UNKNOWN |
| Streaming/vpn_vimeo_A.pcap | Streaming/linked-344af536ded1 | 293 / 0 / 0 | UNKNOWN |
| Streaming/vpn_vimeo_B.pcap | Streaming/linked-344af536ded1 | 235 / 0 / 0 | UNKNOWN |
| Streaming/vpn_youtube_A.pcap | Streaming/linked-344af536ded1 | 806 / 0 / 0 | UNKNOWN |
| VoIP/vpn_facebook_audio2.pcap | VoIP/linked-99e47ec66892 | 1483 / 14 / 0 | UNKNOWN |
| VoIP/vpn_hangouts_audio1.pcap | VoIP/linked-99e47ec66892 | 2860 / 2 / 0 | UNKNOWN |
| VoIP/vpn_hangouts_audio2.pcap | VoIP/linked-99e47ec66892 | 2586 / 152 / 0 | UNKNOWN |
| VoIP/vpn_skype_audio1.pcap | VoIP/linked-99e47ec66892 | 386 / 0 / 0 | UNKNOWN |
| VoIP/vpn_skype_audio2.pcap | VoIP/linked-99e47ec66892 | 362 / 113 / 0 | UNKNOWN |
| VoIP/vpn_voipbuster1a.pcap | VoIP/vpn_voipbuster1 | 204 / 26 / 0 | UNKNOWN |
| VoIP/vpn_voipbuster1b.pcap | VoIP/vpn_voipbuster1 | 202 / 20 / 0 | UNKNOWN |

Counts above are overlapping TShark labels on the 69,321 model-source packets, not encrypted-payload counts. TLS-labelled packets include plaintext handshakes, framing and protected records. SSH observations are concentrated in supplied SFTP captures, but filenames did not determine protocol assignment. Raw UDP additionally has DNS, STUN, RTCP, legacy QUIC and DHT dissections; none survives IPv4/TCP filtering. Occasional heuristic labels, including apparent WireGuard in 2015 traffic, are not accepted as protocol proof. Every capture's raw L4 counts, metadata, server-hello fields and retained labels are saved with evidence/confidence caveats.

## Defensible boundaries and coverage status

An observed Email server hello (`vpn_email2b.pcap`, frame 204) negotiates TLS 1.2 (`0x0303`), cipher suite `0xc02f`, compression 0; other observed suites include `0x002f`. For TLS 1.2 AES-GCM, a future parser can use complete reassembled records and verified negotiation/ChangeCipherSpec state to separate the record header, explicit nonce, protected body and authentication tag. [RFC 5288](https://www.rfc-editor.org/rfc/rfc5288) specifies the 8-byte explicit nonce and 16-byte tag; [RFC 5289](https://www.rfc-editor.org/rfc/rfc5289) identifies the ECDHE AES-GCM suite. These fields establish a candidate protocol, not byte-range coverage of the actual truncated model inputs.

TLS CBC padding and encrypted MAC boundaries cannot simply be guessed without keys. SSH encrypts packet-length/padding fields after key exchange, so a prefix or port does not locate safe body-only ranges. [TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246) and [SSH transport](https://www.rfc-editor.org/rfc/rfc4253) specifications must guide any later parser. Missing handshakes, gaps, truncation, retransmissions and renegotiation require conservative rejection/unknown handling. Unknown UDP regions must not be called OpenVPN ciphertext; the model does not consume UDP in any event.

| Coverage quantity | Current status |
| --- | --- |
| Source captures / usable flows | 31 / 1,674 |
| Model-source packets / nonempty payload packets | 69,321 / 40,962 |
| Actual retained payload bytes | 4,666,377 |
| Confirmed ciphertext packets/bytes, framing, plaintext, tags, padding, unknown bytes | NOT ASSESSED (null) |
| Ciphertext / unknown percentages | NOT ASSESSED (null) |
| Byte ranges transformed / graphs rebuilt | None; transformation phase not reached |

`ciphertext_coverage.json` and `.csv` preserve exact payload denominators by capture, class and candidate acquisition group; category totals are null, with all bytes explicitly marked unassessed. Null is not zero ciphertext or 100% unknown protocol. Protocol-label observations are provided separately and do not substitute for byte coverage. There is no transformation audit pretending validation succeeded; no randomization algorithm/version was instantiated. Proposed ciphertext seed 32 was not applied. No test of packet-specific ciphertext mutation/determinism or graph reconstruction is claimed.

## Interpretation and limitations

No Real-vs-Ciphertext-randomized metrics, paired differences or new scientific ciphertext conclusions exist. The previously observed payload effect could reflect plaintext, framing, application-protocol structure, encrypted regions, session/capture artifacts or optimization behavior. It cannot be attributed to VPN ciphertext. Additional demonstrably independent acquisitions are required first; only then should region identification/coverage, packet-specific SHA-256 randomization, non-ciphertext preservation and complete byte-derived graph reconstruction be implemented and validated before training. Original captures and earlier reports/results/caches remain unchanged; final checks are in `results/capture_disjoint/validation.json`.
