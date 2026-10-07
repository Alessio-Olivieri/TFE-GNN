# PRELIMINARY — original TFE-GNN payload ablation

Prepared for discussion with Federica Bianchi and Prof. Angelo Spognardi.

**This is a one-seed, flow-disjoint pilot. It is not capture-disjoint and may contain capture-level leakage. It does not establish final six-class scientific conclusions.**

## What was run

Original TFE-GNN architecture adapted from the recovered PyTorch Geometric implementation, seed 32, 20 epochs per condition. No CLE-TFE changes. Hyperparameters were fixed before test evaluation; each model checkpoint was selected using validation macro F1 (validation loss breaks ties). Test was evaluated only after selection.

## Exact dataset and preprocessing

Local `../ICSX-VPN`: 31 captures in six category folders, 1674 eligible flows. Capture paths, SHA-256 hashes, packet counts, link types and exclusions are recorded in `results/dataset-audit.json`. One `.pcap` file actually contains PCAPNG.

TCP/IPv4 only. Extract bidirectional five-tuples within each capture; retain packet order and retransmissions, without TCP reassembly or idle timeout. Exclude empty-payload flows and flows with more than 10,000 data packets. Use the first 50 headers and independently the first 50 nonempty payloads per flow, matching upstream filtering. Remove IP addresses/TCP ports using actual header offsets; truncate to 40/150 bytes and pad with token 256. Positive-PMI graphs use window 5 and self loops. Constant inputs get singleton fallback graphs.

Canonical TCP endpoint tuples and identical representations are grouped across captures using transitive closure. The same saved roughly 70/15/15 train/validation/test split is used for every condition. Capture sources are shared across partitions, as explicitly approved for this preliminary pilot. P2P has only one source capture and Email two, so the current collection cannot support three capture-disjoint partitions.

| Class | Retained | Train | Validation | Test |
|---|---:|---:|---:|---:|
| Chat | 183 | 128 | 28 | 27 |
| Email | 138 | 96 | 21 | 21 |
| FileTransfer | 290 | 203 | 44 | 43 |
| P2P | 233 | 163 | 35 | 35 |
| Streaming | 276 | 194 | 41 | 41 |
| VoIP | 554 | 388 | 83 | 83 |
| Total | 1674 | 1172 | 252 | 250 |

## Results

| Condition | Seed | Accuracy | Macro precision | Macro recall | Macro F1 |
|---|---:|---:|---:|---:|---:|
| real | 32 | 0.9320 | 0.9163 | 0.9296 | 0.9221 |
| random | 32 | 0.7600 | 0.6900 | 0.7147 | 0.6934 |
| header-only | 32 | 0.6960 | 0.6813 | 0.6400 | 0.6495 |

Real payload macro F1 is higher than randomized payload in this single run (real minus random: +0.2287). This is a descriptive paired result, not evidence of statistical significance or a general scientific conclusion.

`random` generates seeded uniform bytes for each packet's exact original payload length BEFORE truncation, padding and payload graph construction. Headers (including original checksums), labels, packet order, flow order and split indices are unchanged. Payload RNG is independent of training RNG. `header-only` bypasses the payload encoder and provides a constant zero tensor to fusion. `zero` is available but replaces content with zero bytes while preserving length-dependent padding; it is not equivalent to strict header-only.

Per-class test F1 (test support is identical across conditions):

| Class | Test flows | Real | Random | Header-only |
|---|---:|---:|---:|---:|
| Chat | 27 | 0.7586 | 0.3750 | 0.4186 |
| Email | 21 | 0.9302 | 0.5357 | 0.3889 |
| FileTransfer | 43 | 0.9176 | 0.5641 | 0.4865 |
| P2P | 35 | 1.0000 | 0.9189 | 0.9577 |
| Streaming | 41 | 0.9756 | 0.8235 | 0.9647 |
| VoIP | 83 | 0.9506 | 0.9434 | 0.6806 |

Random also retains payload-length-dependent graph/padding information, while header-only removes the payload branch. Their difference can reflect length information, optimization and the changed effective model; it does not establish that random byte content is useful.

## Important limitations

- These are transport payload bytes, not a verified collection of pure ciphertext. TLS record framing, handshakes, plaintext protocol/control data and incidental background traffic can contribute signal. A real/random difference cannot isolate the contribution of cryptographic ciphertext.
- Labels are inherited from capture folders; every incidental TCP conversation may not represent the named application category. Filtering very long flows can remove principal application traffic.
- Sharing captures may expose capture-specific artifacts. Grouping prevents known duplicate/tuple leakage but cannot prove that all related sessions are identified.
- One seed, a modest and imbalanced dataset, a changed split and a PyG port do not reproduce the paper's published benchmark numbers. No claim of independent-capture generalization is made.
- Gradients accumulate to effective batch 32, but batch normalization uses the smaller physical minibatch. Dynamic header offsets, transport-level payload extraction and singleton graph fallback are documented implementation corrections rather than bit-identical upstream behavior.
- Original header checksums remain unchanged under randomization. They can retain limited content-related information; rewriting them would violate the fixed-header control and requires a separate experiment.

A prefix audit (heuristic, not protocol/decryption validation) found:

| Class | Flows with TLS record prefix | Flows with HTTP method/response prefix | Flows with SSH banner |
|---|---:|---:|---:|
| Chat | 148 | 7 | 0 |
| Email | 132 | 6 | 0 |
| FileTransfer | 145 | 7 | 2 |
| P2P | 8 | 225 | 0 |
| Streaming | 251 | 24 | 0 |
| VoIP | 405 | 37 | 0 |

## Resources and reproducibility

| Condition | Peak CUDA allocated MiB | Peak CUDA reserved MiB | Sampled GPU used MiB | Peak process-tree RSS MiB |
|---|---:|---:|---:|---:|
| real | 4594 | 7548 | 7055 | 4757 |
| random | 4742 | 7600 | 7841 | 4795 |
| header-only | 1743 | 2128 | 2369 | 4768 |

Graphs remain on disk/CPU; only the current minibatch is transferred to CUDA. RAM is sampled every 0.5 s and total device VRAM every 2 s; sampled peaks can miss short excursions. Tree RSS can double-count shared pages. Exact CUDA allocator peaks are reported separately.

- Training source commit: `4bca3256ead2ab2e61dab6b01b7c03abc41cf704`.
- Shared split fingerprint: `adb23f9b794a1a30a19b2bf21e0f0a29a5cccf21e6d1ed622cc21d43a40ed46d`.
- Physical minibatch: 8; accumulation: 4; effective batch: 32.
- Full metrics, per-class metrics, confusion matrices, selected epochs, training histories, commands, software/GPU versions, source hashes and memory measurements: `results/baseline.json` and condition JSON files.
- Human-readable baseline: `results/baseline.txt`; table: `results/comparison.csv`; split indices and flow provenance: `results/splits-seed32.json`.

Sampled peak host memory used (total minus available; includes other applications):

| Condition | Host used GiB | Minimum host available GiB |
|---|---:|---:|
| real | 16.49 | 14.07 |
| random | 14.05 | 16.51 |
| header-only | 13.76 | 16.80 |

No GPU OOM occurred. Random graph preparation overlapped baseline training; device VRAM readings in its preprocessing receipt reflect concurrent device activity. CPU preparation and cache lookup measurements are saved separately in `results/preprocessing-*-seed32.json`.

Commands used:

```sh
/mnt/data/Dev/Spognardi/TFE-GNN/.venv-recovery/bin/python -m recovery.run --payload-mode real --allow-shared-captures
/mnt/data/Dev/Spognardi/TFE-GNN/.venv-recovery/bin/python -m recovery.run --payload-mode random --allow-shared-captures --batch-size 8
/mnt/data/Dev/Spognardi/TFE-GNN/.venv-recovery/bin/python -m recovery.run --payload-mode header-only --allow-shared-captures --batch-size 8
```

Environment: `nix-shell recovery/shell.nix`. See `recovery/README.md` for setup, extraction and repeat-run commands.

## Before drawing conclusions

Repeat paired real/random/header-only conditions over multiple predeclared seeds, acquire enough independent capture sources for capture-disjoint training/validation/testing, validate application labels and encryption boundaries, and distinguish ciphertext from framing/handshake/plaintext signal. Report per-class effects and uncertainty over independent groups. Select hyperparameters using validation data only; reserve new independent test captures for the final protocol.

## Recovery and course provenance

The May 2026 PyG implementation and notebook remain byte-identical to the recovery snapshot. The original commit is preserved by a backup branch and archive. The recovery runner reuses the student's PyG model and graph constructor; fusion and architecture remain upstream-derived. Recovery changes were made with coding-assistant help. This report does not certify independent authorship or course compliance. See `RECOVERY_REPORT.md`. Independent final checks in `results/paired-validation.json` verified all reported metrics, common controls, group separation, all 12 original working files, all 41 archived original files, and all 31 capture hashes.

Official original TFE-GNN: https://github.com/ViktorAxelsen/TFE-GNN (reference commit `e62cb9f1e8b573ae962b0e605f50a1f0daeef1e2`).
