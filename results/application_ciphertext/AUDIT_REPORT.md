# EXPLORATORY TLS 1.2 AES-GCM ciphertext ablation

These results use the existing flow-disjoint evaluation. The available captures cannot support defensible six-class capture-independent evaluation, so capture-level generalization remains unresolved.

## Pre-transformation audit and decision

Status: audit passed for a narrowly named TLS-GCM condition. No transformation or training had been implemented at this decision. Capture-independent evaluation remains stopped.

Protocol evidence: complete clear ClientHello/ServerHello negotiation, supported TLS 1.2 AES-GCM suite, zero compression, per-direction ChangeCipherSpec and expected protected Finished. Complete encrypted Finished, application-data and alert record bodies may be targeted. Record headers, 8-byte explicit nonce and 16-byte authentication tags are excluded. Incomplete records, missing/multiple SYN origins, gaps, conflicting overlaps and unsupported renegotiation are rejected.

Reassembly serves interpretation only. Half-open ranges map back through exact TCP sequence offsets to the original selected packet and its first <=150 bytes. Packet order/length and all samples remain unchanged. 55 bounded Scapy/TShark actual-packet checks and 566 negotiated-suite checks passed with zero disagreement; 40 current tests pass.

SSH encrypted packet/state boundaries are not certified and are excluded. Supported SSH banners and clear HTTP headers are described separately. Unsupported TLS versions/ciphers, ambiguous setup fields, other/unmapped application data and missing-state flows remain unchanged. Entropy, ports, filenames and labels never certify ciphertext.

## Coverage before transformation

| Class | Samples with ciphertext / total | Confirmed bytes | Payload-byte coverage |
| --- | --- | --- | --- |
| Chat | 76/183 | 129,934 | 34.64% |
| Email | 111/138 | 99,066 | 42.20% |
| FileTransfer | 7/290 | 12,320 | 1.22% |
| P2P | 0/233 | 0 | 0.00% |
| Streaming | 93/276 | 230,233 | 41.45% |
| VoIP | 278/554 | 366,903 | 35.23% |

| Partition | Samples with ciphertext / total | Confirmed bytes | Payload-byte coverage |
| --- | --- | --- | --- |
| train | 385/1172 | 582,934 | 17.66% |
| validation | 95/252 | 132,191 | 18.83% |
| test | 85/250 | 123,331 | 18.61% |

Global: 565/1674 samples; 11,316/40,962 packets; 838,456/4,666,377 retained payload bytes (17.97%). Padding tokens are excluded from byte denominators.

| Classified byte category | Bytes |
| --- | --- |
| ciphertext | 838,456 |
| framing | 140,435 |
| plaintext | 237,498 |
| authentication | 105,631 |
| padding | 0 |
| unknown | 3,184,323 |
| unsupported | 160,034 |

Zero identified padding is not proof of no padding in unsupported traffic. Unknown and unsupported are disjoint accounting categories; no such bytes will change. Protocol-level, capture-level, effective-group and split/class counts are in ciphertext_coverage.json/.csv. The complete exact-range manifest is data/application_ciphertext/ranges.json.gz; its digest is recorded in coverage JSON.

## Scientific scope

The fixed held-out set contains confirmed ranges in Chat (16/27), Email (20/21), Streaming (11/41), and VoIP (38/83). FileTransfer (0/43) and P2P (0/35) test inputs have no target ranges. This is not evidence that those classes lack encryption: unsupported/ambiguous regions are deliberately excluded. Coverage is class-associated and the intervention has different strengths by class. The full original six-class test set must remain the primary evaluation; any affected-subset result is secondary. No ciphertext-wide or capture-independent conclusion is permitted.

The 85 affected test samples and 18.61% targeted test bytes provide a nontrivial exploratory TLS-GCM contrast across four classes. Presence is mixed within several classes; it is not a nearly perfect six-class label proxy. coverage_decision.json records every pre-transformation gate. Transformation correctness, determinism, graph reconstruction and source-integrity validation remain required before training.

## Preprocessing and provenance

The existing runner directly extracts source PCAP/PCAPNG to bidirectional IPv4/TCP tuples, flows.json.gz, capped/padded byte sequences and packet-local PMI graphs. SplitCap/per-flow PCAP export/NPZ scripts are not executed in this adapted pipeline. The exact saved results/splits-seed32.json is reused without regeneration. First 50 headers and independently first 50 nonempty payloads, 40/150-byte caps, pad token 256 and PMI window 5 remain fixed. No globally fitted feature statistics were introduced.

The model is an adapted PyTorch Geometric reimplementation of original TFE-GNN with recovery corrections and project evaluation infrastructure; it is not a complete from-scratch implementation. No original src/ model or existing runner file was changed. The TLS parser/audit are newly implemented here from protocol specifications, with independent dissector corroboration.

Protocol references: [TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246), [TLS AES-GCM](https://www.rfc-editor.org/rfc/rfc5288), [ECDHE AES-GCM](https://www.rfc-editor.org/rfc/rfc5289), [SSH transport](https://www.rfc-editor.org/rfc/rfc4253).

## Execution status

Transformation and training are pending. No accuracy or ciphertext-contribution conclusion is claimed at this stage.
