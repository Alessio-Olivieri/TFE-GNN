# Capture-independent TFE-GNN evaluation: STOP before training

Objective: test whether the previous payload advantage survives independent source acquisitions. Status: **no valid six-class capture-independent protocol can be constructed from the supplied captures**. No pilot, full run, checkpoint selection, new predictions, new metrics or paired condition differences were produced. This is a scientific feasibility result, not an accuracy experiment.

## Provenance and protocol

| Class | Raw PCAPs | Candidate acquisition groups | Usable samples |
| --- | --- | --- | --- |
| Chat | 10 | 1 | 183 |
| Email | 2 | 1 | 138 |
| FileTransfer | 6 | 3 | 290 |
| P2P | 1 | 1 | 233 |
| Streaming | 5 | 1 | 276 |
| VoIP | 7 | 2 | 554 |

The 31 recordings form 9 effective conservative acquisition candidates with unverified mutual independence (18 initial activity families, then conservative transitive session links). P2P occurs only in `P2P/vpn_bittorrent.pcap` (233 samples); Email only in the overlapping `Email/vpn_email2a.pcap` and `Email/vpn_email2b.pcap` group (138 samples). Final Chat and Streaming groups also fail the two-group requirement because their activity recordings are linked by reused canonical TCP tuples. A single group cannot occupy both train and test without leakage. Three-way splitting and all-class two-fold CV both fail. Zero capture leakage was not claimed for a nonexistent split. No classes were removed or isolation rules weakened. See [complete feasibility evidence](RESULTS_CAPTURE_FEASIBILITY.md), `results/capture_disjoint/session_link_evidence.json` and `group_evidence.json`.

`provenance_manifest_effective.json` preserves all 1,674 sample IDs, labels, source hashes through the final inventory, canonical tuple/content hashes and effective candidate groups. Automated assertions reject missing/duplicate mappings, changed labels/source identities and group overlap for three-way or per-fold assignments. Grouping and feasibility are invariant to traversal order. No capture split/fold manifest exists; the earlier flow split is preserved exactly and is not relabelled capture-independent. Initial activity inventory and provenance are retained as intermediate audit evidence.

## Preprocessing leakage audit

The adapted runner performs direct source capture → bidirectional IPv4/TCP tuples → `flows.json.gz` → per-packet PyG graphs. It does not execute SplitCap, per-flow PCAP export or NPZ extraction; those actual-stage counts are null. Source identity is retained in `capture`; sample ID hashes the source capture SHA-256 plus canonical tuple hash. Existing `source_family` is a filename heuristic; this audit additionally groups overlapping numbered VoIP pairs. Tuples have no idle timeout and retransmissions remain. Empty-payload flows and flows with more than 10,000 nonempty payload packets are excluded using fixed rules.

Sample-local/deterministic: remove IPv4 addresses/TCP ports; first 50 headers including ACK-only packets; independently first 50 nonempty TCP payloads; 40/150 byte caps; padding token 256; fixed byte vocabulary; PMI/co-occurrence computed within each individual padded packet using window 5 and PMI > 0. There is no corpus-fitted PMI, vocabulary, normalization, threshold or feature selection. PMI weights are calculated for edge selection; the recovered PyG Data stores node bytes and topology, not those computed PMI weights. Existing graph caches therefore do not embed globally estimated corpus statistics. Class counts/content hashes are grouping metadata, not fitted model features.

Learned quantities: neural network weights and BatchNorm running statistics, updated during training only; held-out evaluation uses `model.eval()`. No new fitting occurred. No fold-local correction is needed for currently sample-local graph statistics. A future ciphertext mutation must still happen BEFORE graph construction, rebuilding every byte-dependent feature/topology; unmodified real-payload graphs cannot be reused for transformed bytes. `preprocessing_audit.json` records this audit. No prior graph/cache was changed.

The existing full-payload randomization remains unchanged: SHA-256 of `seed:sample_id:payload_ordinal:payload`, first 16 digest bytes as big-endian seed, NumPy default_rng uniform uint8 [0,255] for original length, then normal truncation/padding/graph construction. Seed 32 is independent of model training seeds. This procedure was not applied in a new experiment.

## Checkpoint and seeds policy

The requested split seed 32, payload seed 32, training seeds 32/42/52 and common 20-epoch budget were retained as planned configuration only. No test data were used for checkpoint/model/hyperparameter selection. With a feasible three-way capture protocol, validation would select checkpoints. With capture CV lacking independent validation captures, the final epoch-20 checkpoint must be used. No unsafe inner-validation substitute was created.

## Previous results and interpretation

| Condition (previous flow-disjoint only) | Accuracy mean ± sample SD | Macro F1 mean ± sample SD |
| --- | --- | --- |
| real | 92.53% ± 1.51% | 0.9168 ± 0.0165 |
| random | 73.60% ± 14.95% | 0.6716 ± 0.1644 |
| header-only | 79.33% ± 8.62% | 0.7423 ± 0.0824 |

These preserved results use three training seeds, one fixed flow-disjoint split and sample standard deviation (ddof=1); they may contain capture leakage. The nine saved prediction sets were independently rechecked during final validation. No new per-run table is presented because zero capture-independent runs were permitted. Absolute performance changes, variance changes and changes in the payload effect across evaluation boundaries cannot be estimated. The old real-vs-random advantage remains a preliminary within-capture result; the present audit cannot establish how much capture-specific information contributed.

## Implementation, validation and resources

The model remains an **adapted PyTorch Geometric reimplementation of original TFE-GNN**. No model or original `src/` file was modified, no official DGL training was executed and no CLE-TFE was used. New project-written code only audits source provenance, raw-to-model extraction, acquisition grouping, stop rules, transport layers and preservation checks. Cross-gated fusion and other adapted/upstream-derived components retain their earlier attribution.

Existing 15 tests passed before changes. The expanded suite, preservation checks, nine old metric recomputations and source SHA-256 comparisons are recorded in `results/capture_disjoint/validation.json` and `tests-after.txt`. No ciphertext transformation tests are claimed: that phase was not reached. Backup branches and original archive are preserved. Exact audit commands and source commit are in `execution.json`.

Read-only capture/TShark audit: sampled process-tree RSS 0.729 GiB; whole-host RAM 11.721 GiB; sampled device memory 1.0 MiB. Host memory includes unrelated applications; these are audit peaks, not training peaks. No GPU training, OOM or architecture/batch-size changes occurred. Previous training peaks are unchanged historical measurements.

Limitations: acquisition logs/interface provenance absent; candidate groups may still be related; one P2P/Email acquisition prevents the required design; tuple reuse and fixed truncation are inherited representation limitations; no new CV measurements exist to aggregate. A lower future capture-independent score would be evidence to investigate, not automatically a bug.
