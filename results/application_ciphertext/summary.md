# EXPLORATORY TLS 1.2 AES-GCM ciphertext ablation

These results use the existing flow-disjoint evaluation. The available captures cannot support defensible six-class capture-independent evaluation, so capture-level generalization remains unresolved.

## Pre-transformation audit and decision

Status: audit passed for a narrowly named TLS-GCM condition. No transformation or training had been implemented at this decision. Capture-independent evaluation remains stopped.

Protocol evidence: complete clear ClientHello/ServerHello negotiation, supported TLS 1.2 AES-GCM suite, zero compression, per-direction ChangeCipherSpec and expected protected Finished. Complete encrypted Finished, application-data and alert record bodies may be targeted. Record headers, 8-byte explicit nonce and 16-byte authentication tags are excluded. Incomplete records, missing/multiple SYN origins, gaps, conflicting overlaps and unsupported renegotiation are rejected.

Reassembly serves interpretation only. Half-open ranges map back through exact TCP sequence offsets to the original selected packet and its first <=150 bytes. Packet order/length and all samples remain unchanged. 55 bounded Scapy/TShark actual-packet checks and 566 negotiated-suite checks passed with zero disagreement; all 40 audit-stage tests passed, increasing to 48 after transformation tests. Confidence rests on negotiated protocol structure and exact offsets, not recovered keys or independently authenticated/decrypted records.

SSH encrypted packet/state boundaries are not certified and are excluded. Supported SSH banners and clear HTTP headers are described separately. Unsupported TLS versions/ciphers, ambiguous setup fields, other/unmapped application data and missing-state flows remain unchanged. Entropy, ports, filenames and labels never certify ciphertext.

| Conservative protocol assignment | Captures | Samples | Payload packets | Retained bytes | Confirmed ciphertext bytes |
| --- | --- | --- | --- | --- | --- |
| TLS 1.2 AES-GCM | 20 | 566 | 13,209 | 1,392,514 | 838,456 (60.21%) |
| Other/unsupported TLS | 23 | 121 | 1,867 | 245,481 | 0 |
| SSH, unsupported encrypted state | 1 | 2 | 77 | 7,340 | 0 |
| HTTP | 14 | 291 | 9,634 | 1,443,186 | 0 |
| Unknown | 28 | 694 | 16,175 | 1,577,856 | 0 |

These are mutually exclusive conservative sample assignments, not a complete protocol census; capture counts overlap and unknown samples can include unsupported TLS/SSH or other protocols. Of the 566 supported TLS samples, 565 retain at least one confirmed ciphertext byte after the model's byte cap. The visible encrypted layer is application-layer TLS over retained TCP, not OpenVPN UDP tunnel ciphertext.

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

## Completed experiment

These results use the existing flow-disjoint evaluation. The available captures cannot support defensible six-class capture-independent evaluation, so capture-level generalization remains unresolved.

Six fresh sequential runs used training seeds 32/42/52, fixed split seed 32 and fixed ciphertext seed 32. Every run used the existing 20-epoch configuration: batch 8, effective batch 32, Adam, LR .01, cosine schedule, 10% warmup, no architecture/hyperparameter changes. Checkpoints were selected by validation macro F1, ties by validation loss; the full 250-sample test set was evaluated after training. No test-based checkpoint selection or tuning occurred.

| Seed | Condition | Accuracy | Macro F1 | Final train accuracy | Selected epoch |
| --- | --- | --- | --- | --- | --- |
| 32 | real | 93.20% | 0.9221 | 98.89% | 18 |
| 32 | tls12_gcm_randomized | 93.60% | 0.9262 | 98.72% | 19 |
| 42 | real | 93.60% | 0.9300 | 97.01% | 20 |
| 42 | tls12_gcm_randomized | 95.60% | 0.9519 | 98.55% | 20 |
| 52 | real | 90.80% | 0.8982 | 94.80% | 15 |
| 52 | tls12_gcm_randomized | 95.20% | 0.9423 | 98.38% | 19 |

Sample standard deviation uses ddof=1 across the three matched training seeds.

| Condition | Accuracy mean ± SD | Macro F1 mean ± SD |
| --- | --- | --- |
| real | 92.53% ± 1.51% | 0.9168 ± 0.0165 |
| tls12_gcm_randomized | 94.80% ± 1.06% | 0.9401 ± 0.0129 |

| Real minus TLS-GCM randomized | Accuracy difference (pp) | Macro F1 difference |
| --- | --- | --- |
| Seed 32 | -0.40 | -0.0041 |
| Seed 42 | -2.00 | -0.0219 |
| Seed 52 | -4.40 | -0.0440 |
| Mean ± sample SD | -2.27 ± 2.01 | -0.0233 ± 0.0200 |

## Comparison with preserved full-payload/header ablations

| Condition | Accuracy mean ± SD | Macro F1 mean ± SD |
| --- | --- | --- |
| Previous real | 92.53% ± 1.51% | 0.9168 ± 0.0165 |
| Previous random | 73.60% ± 14.95% | 0.6716 ± 0.1644 |
| Previous header-only | 79.33% ± 8.62% | 0.7423 ± 0.0824 |
| TLS-GCM randomized | 94.80% ± 1.06% | 0.9401 ± 0.0129 |

## Transformation and validation

Uniform randomization targeted 838,456 confirmed bytes; 835,125 actually differed, with coincidental equality allowed. All 565 targeted samples, including 85/250 test samples, changed their model graphs. All 83,700 header graphs and all untargeted payload graphs remained semantically identical. The transformed cache was absent before generation; every payload graph was rebuilt by the ordinary packet-local PMI pipeline. No original ciphertext-derived topology/features were reused.

Packet/range streams use compact sorted ASCII JSON of transformation version, global seed, capture SHA, flow ID, packet index and range index/bounds; SHA-256 full digest seeds NumPy PCG64. Order independence was checked on the entire actual dataset and across Python hash seeds. Headers, record framing/nonce, hello plaintext, authentication tags, unknown/unsupported bytes, labels, source identity, lengths, packet order/count and split membership were preserved. TLS authentication would fail after mutation by design; the experiment modifies derived model inputs, not wire-valid traffic.

All 48 tests passed after execution. Metrics/confusion matrices were independently recomputed for all six runs. All three fresh Real runs reproduced the previous corresponding baseline exactly. All 31 source SHA-256 values, 131 pre-experiment tracked files, original graph caches, backup branches and archive remain unchanged. Integrity was checked before implementation, after transformation, after each run and finally.

## Interpretation and limitations

TLS-GCM randomization increased both held-out metrics in all three matched seeds. Its mean improvement over Real was 2.27 percentage points in accuracy and 0.0233 in macro F1; the paired Real-minus-randomized differences are negative above. This experiment therefore provides no evidence that the original values of these particular confirmed TLS ciphertext regions improve classification under this setup. It is neither an equivalence test nor evidence that encrypted bytes are universally uninformative.

The earlier large full-payload-randomization degradation is not reproduced by targeting only these supported TLS ciphertext ranges. Non-ciphertext framing/plaintext and other untouched or unsupported regions remain plausible contributors to that earlier payload advantage. This experiment cannot determine their relative contributions, isolate every encrypted protocol, or rule out information in unmodified tags/nonces and unknown encrypted regions.

The unexpected direction was investigated without additional runs or tuning. Matched initializations/hyperparameters/sample identities agree; all three Real baselines reproduce exactly; independent byte, graph, metric and source-integrity checks pass. Final training losses were Real/TLS-randomized 0.0354/0.0355 (seed 32), 0.0916/0.0484 (42), and 0.1455/0.0484 (52). The lower transformed training loss in seeds 42/52 suggests optimization-path or representation effects warrant investigation. Fixed random perturbations could also have a regularization-like effect; none of these explanations is established by this experiment.

Secondary descriptive analysis uses the pre-audited affected subset, without replacing the full test set:

| Seed | Affected test samples correct, Real / TLS-randomized (out of 85) | Unchanged-input test samples correct (out of 165) |
| --- | --- | --- |
| 32 | 84 / 84 | 149 / 150 |
| 42 | 84 / 85 | 150 / 154 |
| 52 | 75 / 85 | 152 / 153 |

Predictions also changed on unchanged test inputs because the training data and learned model changed. This is expected and does not indicate those test inputs were mutated. Full six-class metrics above remain primary. Machine-readable diagnostic checks are in interpretation_checks.json and secondary_subset_accuracy.csv.

These results use the existing flow-disjoint evaluation. The available captures cannot support defensible six-class capture-independent evaluation, so capture-level generalization remains unresolved.

Only one fixed split and one transformation seed were used. Three model seeds are repeated measurements on the same captures/test samples, not independent datasets or confidence intervals. The test set was previously observed. Coverage is protocol- and class-associated: FileTransfer/P2P test inputs are untouched, and much payload remains unknown/unsupported. Encrypted Finished and alert bodies are included along with application-data ciphertext; explicit nonces/tags remain. Changing training bytes can alter predictions even for unaffected test inputs. The separate secondary_subset_accuracy.csv is descriptive post-hoc analysis on the pre-audited 85 affected and 165 unaffected samples, not a replacement test set. Optimization, byte-graph representation, protocol implementations, background flows and capture/session artifacts remain alternative explanations. No additional seeds, classes or test subsets were selected to improve results.

## Resources

| Seed | Condition | Sampled device VRAM GiB | CUDA reserved GiB | Process-tree RSS GiB | Host RAM GiB |
| --- | --- | --- | --- | --- | --- |
| 32 | real | 7.42 | 7.37 | 4.64 | 13.97 |
| 32 | tls12_gcm_randomized | 6.89 | 7.37 | 4.92 | 14.09 |
| 42 | real | 7.44 | 7.21 | 4.74 | 14.12 |
| 42 | tls12_gcm_randomized | 7.44 | 7.20 | 4.93 | 14.14 |
| 52 | real | 7.60 | 7.37 | 4.64 | 13.98 |
| 52 | tls12_gcm_randomized | 7.60 | 7.37 | 4.92 | 14.17 |

Runs were sequential; no OOM or retries/configuration changes. Only minibatches were transferred to CUDA. RAM/device sampling can miss brief peaks and includes other processes; CUDA allocator peaks are exact.

Maximum recorded training usage was 7.60 GiB sampled device VRAM, 7.37 GiB CUDA allocator reserved, 4.93 GiB process-tree RSS and 14.17 GiB host RAM. Fresh graph preparation recorded 14.35 GiB host RAM; its receipt is transformation_validation.json. These are sampled resource observations, not a guarantee that every transient host/device peak was captured.

## Reproduction and outputs

Run from TFE-GNN inside nix-shell recovery/audit-shell.nix with .venv-recovery/bin/python. Stages: -m recovery.application_audit; -m recovery.application_check; coverage_decision.json review; -m recovery.application_transform; -m recovery.application_prepare; -m recovery.application_validate_graphs; -m recovery.application_experiment --stage pilot; pilot review; --stage full; -m recovery.application_summary. Scripts refuse overwriting completed artifacts. The initial audit-only report is preserved as AUDIT_REPORT.md.

All result CSV/JSON, bounded parser/transformation evidence, validation, and test logs are under results/application_ciphertext/. Individual seed_{32,42,52}/{real,tls12_gcm_randomized}.json include complete predictions/labels, per-class metrics, confusion matrices, all epoch histories, software/GPU versions, seeds, commands, source hashes and commit. Range and derived-input/graph caches remain under data/application_ciphertext/ (not committed generated data). Checkpoints/logs are under checkpoints/application_ciphertext/ and logs/application_ciphertext/.

Source commits: 47bac9c contains the retained-protocol parser/audit and pre-transformation coverage decision; 33904f1 contains deterministic transformation, fresh-graph validation, tests, gated training and aggregation infrastructure. All six fresh runs use source commit 33904f1 with identical source-file hashes. Existing model and runner files remain unchanged. Results are preserved in a separate subsequent commit.
