# PRELIMINARY fixed-split multi-seed ISCX-VPN experiment

Objective: measure training variability while comparing captured payload, randomized payload, and header-only TFE-GNN.

Training/model seeds: **32, 42, 52**. Split seed: **32**. Payload-transformation seed: **32**, fixed across training seeds.
All nine runs were newly trained for 20 epochs, sequentially; best checkpoint selected by validation macro F1 (ties: validation loss). Test evaluation occurred after training.

## Fixed-split methodology

Reused the pilot manifest `results/splits-seed32.json` without regeneration. File SHA256: `c319605abf36869be194e3541d0f080a34e8581c013f051a72556ea246a07e57`. Sample/group assignment fingerprint: `adb23f9b794a1a30a19b2bf21e0f0a29a5cccf21e6d1ed622cc21d43a40ed46d`.
Canonical bidirectional TCP endpoint tuples and identical representations are grouped transitively across captures. Identical sample IDs, group membership, ordered indices, labels, and split fingerprints were checked across all nine runs.
**This is flow-disjoint, not capture-disjoint.** Some samples in train, validation and test originate from the same captures (24 captures appear in all three). Capture-level leakage remains possible.

## Dataset and preprocessing

ISCX-VPN2016: the same 31 local original captures in `../ICSX-VPN`, six folder labels. IPv4/TCP only; bidirectional endpoint-tuple flows per capture, no idle timeout or reassembly, retransmissions retained. Exclude empty-payload flows and flows with >10,000 nonempty data packets. First 50 TCP headers (including ACK-only packets) and independently first 50 nonempty payloads; remove IP addresses/TCP ports, truncate to 40/150 bytes, pad with token 256, PMI window 5.

| Class | Total | Train | Validation | Test |
|---|---:|---:|---:|---:|
| Chat | 183 | 128 | 28 | 27 |
| Email | 138 | 96 | 21 | 21 |
| FileTransfer | 290 | 203 | 44 | 43 |
| P2P | 233 | 163 | 35 | 35 |
| Streaming | 276 | 194 | 41 | 41 |
| VoIP | 554 | 388 | 83 | 83 |
| **Total samples** | **1674** | **1172** | **252** | **250** |
| **Distinct groups** | **1621** | **1135** | **242** | **244** |

Randomization uses the unchanged pilot procedure: SHA256 of `32:{sample_id}:{packet_ordinal}:payload`, first 16 bytes interpreted big endian as NumPy default_rng/PCG64 seed; uniformly random uint8 bytes of the full original packet payload length, before truncation, padding and graph construction. Reuses the pilot `random-32` graphs. Headers, labels, lengths, packet order and splits remain unchanged. Fixing this transformation isolates training variability; payload-randomization variability is not measured. Header-only bypasses the payload encoder and supplies a constant zero vector to fusion; it removes payload length information from that branch too.

## Training configuration

Same recovered original TFE-GNN PyG model, not CLE-TFE. Embedding 64, four GraphSAGE layers of width 128, cross-gated fusion, two-layer bidirectional LSTM hidden width 1024. Adam LR 0.01, 10% warmup then cosine to 0.0001, dropout 0.2, no weight decay/label smoothing, FP32. Minibatch 8, accumulation 4 (effective 32); BatchNorm sees 8 samples, as in the pilot. No test-set tuning.
Seed Python, NumPy, Torch CPU/CUDA and DataLoader generators by training seed. Worker Python/NumPy RNGs use `torch.initial_seed() % 2**32`; Torch seeds workers automatically. `PYTHONHASHSEED=32` is held fixed. Deterministic Torch algorithms, deterministic cuDNN, no benchmarking/TF32; CUBLAS_WORKSPACE_CONFIG=:4096:8. Graph caches remain on CPU/disk and only current minibatches transfer to CUDA.

Source commit used by all runs: `836e3db293590944226d7cdd2b52843647ae5f69`. Exact commands, software/GPU versions, configuration, RNG metadata, predictions, class metrics and epoch histories are in every individual JSON.

## Per-seed held-out results

| Training seed | Condition | Accuracy | Macro F1 | Test loss | Best epoch |
|---:|---|---:|---:|---:|---:|
| 32 | Real payload | 93.20% | 0.9221 | 0.2804 | 18 |
| 32 | Randomized payload | 76.00% | 0.6934 | 0.6087 | 17 |
| 32 | Header-only | 69.60% | 0.6495 | 0.7713 | 16 |
| 42 | Real payload | 93.60% | 0.9300 | 0.1696 | 20 |
| 42 | Randomized payload | 87.20% | 0.8240 | 0.3457 | 19 |
| 42 | Header-only | 82.40% | 0.7707 | 0.4690 | 20 |
| 52 | Real payload | 90.80% | 0.8982 | 0.2434 | 15 |
| 52 | Randomized payload | 57.60% | 0.4974 | 1.1265 | 19 |
| 52 | Header-only | 86.00% | 0.8067 | 0.3951 | 15 |

## Mean ± sample standard deviation

Sample standard deviation uses **ddof=1** across three training seeds. Accuracy is percent; paired accuracy differences are percentage points. Macro F1 and its differences use the 0–1 scale.

| Condition | Accuracy mean ± std | Macro F1 mean ± std |
|---|---:|---:|
| Real payload | 92.53% ± 1.51% | 0.9168 ± 0.0165 |
| Randomized payload | 73.60% ± 14.95% | 0.6716 ± 0.1644 |
| Header-only | 79.33% ± 8.62% | 0.7423 ± 0.0824 |

## Paired differences

| Comparison | Seed | Accuracy difference (pp) | Macro F1 difference |
|---|---:|---:|---:|
| real - random | 32 | +17.20 | +0.2287 |
| real - random | 42 | +6.40 | +0.1060 |
| real - random | 52 | +33.20 | +0.4008 |
| random - header-only | 32 | +6.40 | +0.0439 |
| random - header-only | 42 | +4.80 | +0.0533 |
| random - header-only | 52 | -28.40 | -0.3093 |
| real - header-only | 32 | +23.60 | +0.2726 |
| real - header-only | 42 | +11.20 | +0.1593 |
| real - header-only | 52 | +4.80 | +0.0915 |

| Comparison | Accuracy difference mean ± std (pp) | Macro F1 difference mean ± std |
|---|---:|---:|
| real - random | +18.93 ± 13.48 | +0.2451 ± 0.1481 |
| random - header-only | -5.73 ± 19.65 | -0.0707 ± 0.2067 |
| real - header-only | +13.20 ± 9.56 | +0.1745 ± 0.0915 |

## Validation and resources

- All nine runs completed 20 epochs with the unchanged pilot hyperparameters and no OOM retries.
- All nine share the exact pilot split file and sample/group membership. No tuple/content/group overlap across partitions.
- Accuracy, macro F1 and confusion matrices independently recomputed from all nine saved prediction/label arrays (tolerance 1e-12).
- Matching initial model states within each training seed; three distinct initial states across seeds. Common committed source hashes.
- All 15 existing recovery and new seed/split/aggregation tests passed before and after execution; see `tests-before.txt` and `tests-after.txt`.
- All 31 original capture SHA256 hashes match both the pilot audit and the pre-experiment snapshot. All 36 existing non-recovery tracked artifacts remain byte-identical, including preliminary results/reports.
- The original backup branch and archive, and all 5,022 header/real/random cached graph files, passed integrity checks.
- Seed-32 reproduction versus pilot: `{"header-only": {"accuracy_difference": 0.0, "macro_f1_difference": 0.0, "predictions_identical": true}, "random": {"accuracy_difference": 0.0, "macro_f1_difference": 0.0, "predictions_identical": true}, "real": {"accuracy_difference": 0.0, "macro_f1_difference": 0.0, "predictions_identical": true}}`.

| Seed | Condition | Peak device VRAM (GiB) | Peak CUDA reserved (GiB) | Peak process-tree RSS (GiB) | Peak host used (GiB) |
|---:|---|---:|---:|---:|---:|
| 32 | Real payload | 6.89 | 7.37 | 4.67 | 14.02 |
| 32 | Randomized payload | 7.66 | 7.42 | 4.76 | 14.03 |
| 32 | Header-only | 2.31 | 2.08 | 4.66 | 14.17 |
| 42 | Real payload | 7.44 | 7.21 | 4.68 | 14.29 |
| 42 | Randomized payload | 7.05 | 7.17 | 4.75 | 14.31 |
| 42 | Header-only | 2.31 | 2.07 | 4.62 | 14.18 |
| 52 | Real payload | 7.60 | 7.37 | 4.67 | 14.14 |
| 52 | Randomized payload | 7.55 | 7.31 | 4.67 | 14.18 |
| 52 | Header-only | 2.43 | 2.20 | 4.68 | 14.13 |

VRAM sampled every 2 seconds and RAM every 0.5 seconds; CUDA allocator peaks are exact. Sampling can miss brief spikes, summed RSS can double-count shared pages, and host/device totals include other processes.

## Interpretation and limitations

Across these three fixed-split training seeds, the mean real-minus-random accuracy difference is +18.93 percentage points and the mean macro-F1 difference is +0.2451. This compares retained payload byte content with length-preserving randomized bytes on this pilot.
Assess the observed effect using the tables above; these are preliminary fixed-split training-seed results, not final six-class scientific conclusions. Retained transport payload may include plaintext, protocol framing, handshakes and incidental/background traffic. This comparison does **not** isolate encrypted ciphertext itself.
Real payload exceeded randomized payload and header-only in accuracy and macro F1 for all three training seeds. However, randomized payload did not consistently improve over header-only: the paired accuracy differences were +6.4, +4.8, and -28.4 percentage points for seeds 32, 42, and 52. Its mean performance was below header-only, with large seed variability. This is not evidence of a reliable benefit from retaining randomized payload graphs.

The randomized seed-52 run finished with training accuracy 61.52%, training loss 1.0064, and validation macro F1 0.5084 at epoch 20 (best validation macro F1 0.5207 at epoch 19). All runs used the same fixed 20-epoch budget without retries or condition-specific tuning. The weaker learning curve is consistent with incomplete optimization under this budget; that is an interpretation, not a diagnosis of its cause. Differences may reflect optimization difficulty as well as useful input information. Longer training or alternative settings should be evaluated in a separately declared experiment using validation data, never selected against these test results.

Payload byte content improves observed classification performance on this ISCX-VPN pilot under the tested training setup. Because retained payload can contain plaintext/protocol framing, this does not isolate the contribution of encrypted ciphertext itself.

Three training seeds characterize initialization/training variability on one selected split and one fixed randomization; they are not independent datasets, confidence intervals, or evidence of capture-disjoint generalization. Capture-folder labels may include background flows, and excluding very long flows can remove primary application traffic. The pilot was already observed; this is not a new untouched test set. PyG recovery and minibatch-8 BatchNorm are documented differences from upstream and this is not an exact published-result reproduction.
Before stronger conclusions: obtain enough independent captures for capture-disjoint partitions, validate per-flow labels and encryption boundaries, isolate ciphertext versus framing/plaintext, repeat across grouped splits and randomization seeds, and quantify uncertainty with appropriate independent source groups. Do not tune on this test set.

## Artifacts and reproduction

Command executed from the repository root: `nix-shell recovery/shell.nix --run '.venv-recovery/bin/python -m recovery.multiseed'`. An interrupted execution can reuse completed run files before aggregation. After completion, existing aggregate outputs are immutable and the command refuses to overwrite them. Use a new output root and matching experiment snapshot for a separate study.
Individual results: `results/multiseed/seed_{32,42,52}/{real,randomized,header_only}.json` (and `.txt`); each includes labels/predictions and class metrics. Checkpoints: `checkpoints/multiseed/seed_{32,42,52}/`; logs: `logs/multiseed/seed_{32,42,52}/`.
Aggregate files: `all_runs.csv`, `summary.csv`, `paired_differences.csv`, `paired_summary.csv`, `summary.md`, `validation.json`, `experiment.json`, `tests-before.txt`, `tests-after.txt` under `results/multiseed/`. Original recovery/preliminary reports, baseline results, backup branch and archive are preserved.
