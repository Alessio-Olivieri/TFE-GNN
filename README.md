# What Information in Encrypted Traffic Actually Helps Classification?

A university study of payload information in a PyTorch Geometric adaptation of
TFE-GNN, using six traffic classes from ISCXVPN2016. The repository contains
reproducible code, saved predictions, and exploratory results; it does not
reproduce the paper's published evaluation protocol.

## Research question

Does the performance gain from packet payloads come from encrypted byte values
themselves, or from other information present in transport payloads?

## Model

The architecture follows **Zhang et al., TFE-GNN (WWW 2023)**: separate header and
payload byte graphs, four mean-GraphSAGE layers per encoder, concatenated layer
readouts, cross-gated fusion, a two-layer bidirectional LSTM, and a six-class head.
`src/model.py` is the canonical implementation. It preserves the initialization,
input dropout, GraphSAGE → PReLU → BatchNorm ordering, parameter names and branch
controls used for the saved experiments. Exact regression checks include the
constructor's RNG state; the upstream DGL and adapted PyG implementations are
not claimed to be bitwise equivalent.

## Experiments

1. **Real:** retain captured TCP payloads.
2. **Full-payload randomized:** replace each original-length payload with uniform
   bytes before truncation, padding and graph construction. Preserve headers,
   lengths, packet order, labels and splits.
3. **Header-only:** bypass the payload encoder and supply zeros to fusion. This
   removes payload length information from that branch as well as byte content.
4. **TLS 1.2 AES-GCM randomized:** replace only conservatively identified
   ciphertext ranges, then rebuild all byte-dependent graphs. Preserve record
   framing, explicit nonces, tags, cleartext, and unknown/unsupported bytes.
   Protected Finished and alert bodies are included alongside application data.

Both randomizations transform inputs; they use the same neural architecture as
Real. `payload-only` and a length-preserving zero-byte control remain available
as diagnostics, with no published results claimed here.

## Main results

Mean ± sample SD (`ddof=1`) across training seeds **32, 42, 52**; one fixed
flow-disjoint split and one fixed intervention seed, both **32**.

| Condition | Accuracy | Macro F1 |
|---|---:|---:|
| Real | 92.53% ± 1.51% | 0.9168 ± 0.0165 |
| Full-payload randomized | 73.60% ± 14.95% | 0.6716 ± 0.1644 |
| Header-only | 79.33% ± 8.62% | 0.7423 ± 0.0824 |
| TLS-GCM randomized | 94.80% ± 1.06% | 0.9401 ± 0.0129 |

The TLS experiment's three Real runs exactly reproduced the earlier baselines.
CSV summaries, per-seed contrasts and the original saved prediction/history
fields are in [`results/`](results/README.md). The notebook reads these saved
outputs without training.

## Key finding

**Payload helps ≠ ciphertext helps.** Within this flow-disjoint evaluation,
randomizing confidently identified TLS 1.2 AES-GCM ciphertext did not reduce
classification performance. This is an observed paired contrast, not a
statistical equivalence test or a claim that ciphertext is universally useless.

The intervention targets **838,456 / 4,666,377 retained payload bytes (17.97%)**
in **565 / 1,674 samples**, including **85 / 250 test samples**. Coverage is
uneven: FileTransfer and P2P test inputs are untouched. Much payload remains
unknown or unsupported. Untouched plaintext, framing, protocol structure,
optimization effects and capture artifacts remain possible explanations.

## Capture-independence limitation

**The available captures cannot support defensible six-class capture-independent
evaluation.** P2P has one recording; Email's two recordings overlap and form one
conservative acquisition group. Related TCP tuples also join Chat and Streaming
activities. The final candidate-group counts are 1/1/3/1/1/2 for
Chat/Email/FileTransfer/P2P/Streaming/VoIP; even these groups have unverified mutual
independence. No capture-independent split, training run, or generalization score
was produced. Dividing a recording into flows or time slices does not supply
independent acquisitions.

The reported split groups endpoint tuples and identical representations
transitively, but shares capture sources between partitions. Three training seeds
measure training variability on the same 250 test samples, not independent data
replication or confidence intervals. The test set was previously observed. Folder
labels can include background traffic, and fixed long-flow exclusions can remove
primary application flows. The retained traffic is IPv4/TCP application traffic;
the capture interface is unknown and UDP OpenVPN tunnel bytes are excluded.

## Repository structure

| Path | Purpose |
|---|---|
| `src/` | Canonical model, packet extraction, PMI graphs, saved splits and training |
| `experiments/` | Payload runs, TLS parsing/transformation, capture audits and result verification |
| `tests/` | Original 48 tests plus equivalence, evidence and scientific-kernel regression checks |
| `results/` | Compact published CSVs, saved predictions/histories, provenance and fixed split |
| `notebooks/encrypted_traffic_ablation.ipynb` | Course-facing analysis of saved results |

## Reproduction

From the repository root with Python 3.12:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r experiments/requirements-resolved.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m experiments.verify_results
```

On NixOS, enter `nix-shell experiments/shell.nix` first. Tests run on CPU without
PCAPs or checkpoints. `verify_results` uses the Python standard library only.
The resolved requirements record the validated environment; the optional Nix
shell uses the host Nixpkgs channel and is not independently locked.

To reproduce inputs or train new runs, obtain the original captures separately
and follow [`experiments/README.md`](experiments/README.md). It specifies the
saved split, exact seeds/settings, fresh output directories, and TLS checks.
Reproducing training requires an appropriate CUDA environment; exact execution
across hardware/library versions is not guaranteed. No training is needed to
inspect or validate the published results.

## Dataset

[ISCXVPN2016, Canadian Institute for Cybersecurity, UNB](https://www.unb.ca/cic/datasets/vpn.html).
The local study uses 31 captures and 1,674 eligible samples, with 1,172/252/250
train/validation/test samples. IPv4/TCP tuples are grouped bidirectionally per
capture, retaining retransmissions without an idle timeout. First 50 headers and
independently first 50 nonempty payloads are capped at 40/150 bytes and padded
with token 256; PMI graphs use window 5. IP addresses and TCP ports are removed;
checksums and other header fields remain. Graph statistics are packet-local.
See the experiment guide for exclusions and the source-hash manifest. Raw
captures, derived data, graphs and checkpoints are not redistributed.

## Attribution

Architecture and upstream-derived fusion/temporal components come from the
[official TFE-GNN implementation](https://github.com/ViktorAxelsen/TFE-GNN),
reference revision `e62cb9f1e8b573ae962b0e605f50a1f0daeef1e2`, under Apache 2.0.
The original license is preserved in [`LICENSE`](LICENSE); [`NOTICE`](NOTICE)
describes adaptations. This project includes AI-assisted implementation and
analysis tooling and does not claim independent invention of the architecture.

The complete research snapshot is preserved locally on
`archive/research-full-2026-10-08` at `121f484`. Its development reports and receipts
remain recoverable. Existing scientific milestone commits retain their original
authors and dates; publication cleanup is recorded in subsequent commits.

## References

- Zhang et al. (2023), *TFE-GNN: A Temporal Fusion Encoder Using Graph Neural Networks
  for Fine-grained Encrypted Traffic Classification*, WWW, pp. 2066–2075.
  [Paper and official implementation](https://github.com/ViktorAxelsen/TFE-GNN).
- Draper-Gil et al. (2016), *Characterization of Encrypted and VPN Traffic Using
  Time-Related Features*, ICISSP, pp. 407–414.
  [Dataset and citation](https://www.unb.ca/cic/datasets/vpn.html).
- [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246),
  [RFC 5288](https://www.rfc-editor.org/rfc/rfc5288), and
  [RFC 5289](https://www.rfc-editor.org/rfc/rfc5289): TLS 1.2 and AES-GCM suites.
