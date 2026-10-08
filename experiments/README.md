# Reproduction guide

Run commands from the repository root, with the Python 3.12 environment from the
main README activated. On NixOS, use `nix-shell experiments/audit-shell.nix` for
TShark and the Torch runtime libraries. Set the deterministic environment before
starting Python:

```sh
export CUBLAS_WORKSPACE_CONFIG=:4096:8 PYTHONHASHSEED=32
export OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=4
python -m unittest discover -s tests -v
python -m experiments.verify_results
```

The test suite and result verification require neither source captures nor a GPU.
All commands below are optional reproduction work. They are not run by tests or
the notebook. Use fresh `outputs/` directories; never overwrite published results.

## Inputs and preprocessing

Obtain the exact 31 source captures identified by
`results/capture_audit/source_sha256.json`, arranged in folders named Chat, Email,
FileTransfer, P2P, Streaming and VoIP. For example, put them in `dataset/iscx-vpn/`.
They are not included in this repository.

```sh
python -m src.capture --data-root dataset/iscx-vpn --output data/recovery
```

The historical `data/recovery` cache name remains stable to support existing local
graph inputs. It is ignored by Git. The extractor refuses an existing output
folder; existing validated local caches can be reused.

Read PCAP/PCAPNG by magic. Keep valid unfragmented IPv4/TCP; group each canonical
endpoint pair bidirectionally within its capture, without idle timeout or stream
reassembly. Retain retransmissions. Exclude flows with no nonempty payload or
more than 10,000 nonempty payload packets. Keep independently the first 50 headers
and the first 50 nonempty payloads. Remove IP addresses and ports with actual IP
header length, preserving options, checksums, sequence numbers and other fields.
Cap header/payload sequences at 40/150 bytes, pad with token 256, and construct
packet-local positive-PMI graphs with window 5 and self loops. PMI weights select
edges but do not weight GraphSAGE. Constant/padding inputs use the existing
singleton/fallback graphs. The original graph-constructor boundary behavior is
retained; callers supply padded nonempty sequences.

The saved `results/splits-seed32.json` is mandatory for the published comparison.
`src.train.read_split` validates identity, labels, tuple/content/group isolation,
ordered indices and fingerprints before use. It never regenerates an explicitly
supplied manifest. Canonical tuples and identical representations are joined
transitively across captures. The split is flow-disjoint and shares capture
sources; `--allow-shared-captures` explicitly acknowledges this limitation.

## Payload experiment

The following command starts nine new training runs sequentially:

```sh
python -m experiments.multiseed --data data/recovery \
  --output outputs/payload-repeat
```

For one condition, or preparation without training:

```sh
python -m src.train --payload-mode real --data data/recovery \
  --training-seed 32 --split-seed 32 --payload-seed 32 \
  --split-manifest results/splits-seed32.json --allow-shared-captures \
  --results outputs/one-run --checkpoints outputs/one-run/checkpoints \
  --log-dir outputs/one-run/logs --prepare-only
```

Remove `--prepare-only` to train. Modes are `real`, `random`, `header-only`,
`payload-only` and `zero`. Randomization uses SHA-256 of
`32:{sample_id}:{payload_ordinal}:payload`; the first 16 digest bytes seed NumPy
PCG64. Generate the full original-length payload before capping/padding and
building graphs. Randomization never consumes the training RNG.

All published runs use embedding 64, four GraphSAGE layers of width 128, LSTM
hidden width 1024, 20 epochs, FP32, Adam LR .01, 10% warmup and cosine decay to
.0001, no weight decay or label smoothing. Minibatch 8, accumulation 4 gives
effective batch 32; BatchNorm sees minibatches of 8. Training seeds are 32/42/52;
split and intervention seeds are always 32. Select the checkpoint by validation
macro F1, breaking ties with validation loss; evaluate test afterward. No test
selection or tuning is part of these commands. The original training routine
retains its OOM retry behavior; the recorded runs had no retries. Any retry
changes the matched batch configuration and must not be pooled with these results.

## Capture audit

```sh
python -m experiments.capture_analysis --capture-root dataset/iscx-vpn \
  --data data/recovery --output outputs/capture-repeat
```

This verifies source hashes and exact cached model bytes, groups related activity
captures and shared tuples/representations conservatively, and compares the
feasibility decision with the published STOP. It does not create a capture split
or train a model. Candidate groups do not certify independent acquisitions.
Transport-layer and timestamp evidence helpers remain in `capture_audit.py` and
`capture_audit_report.py`; the retained-layer CSVs are in `results/capture_audit/`.

## TLS 1.2 AES-GCM experiment

TShark must be on PATH. Preparation re-extracts protocol evidence and builds fresh
transformed graphs, without training:

```sh
python -m experiments.tls_prepare --capture-root dataset/iscx-vpn \
  --data data/recovery --output outputs/tls-inputs
```

The original conservative parser requires SYN-anchored gap/conflict-free prefixes,
clear ClientHello/ServerHello negotiation, supported TLS 1.2 AES-GCM, zero
compression, ChangeCipherSpec and the expected protected Finished. Suite checks
are corroborated by TShark; bounded packet-offset checks use Scapy and TShark PDML.
Ambiguous/incomplete or unsupported bytes remain unchanged. Interpretation uses
reassembly, but transformation maps ranges back to the selected original packets.

The existing transformation derives independent PCG64 streams from canonical
sorted compact ASCII JSON containing version, seed 32, capture hash, sample ID,
packet index and ciphertext-range index/bounds, using the full SHA-256 digest as
a big-endian integer. Nonces, tags, framing and all untargeted bytes are preserved.
Authentication would fail after mutation; these are derived classifier inputs,
not wire-valid packets. The command requires exact agreement with the recorded
range-manifest hash, transformed-input hash and coverage CSV, checks traversal
independence, rebuilds transformed graphs, and checks unchanged header/untargeted
graphs. Differences stop preparation.

One new paired condition can then be trained with:

```sh
python -m experiments.tls_experiment --condition real --training-seed 32 \
  --data data/recovery --prepared outputs/tls-inputs --output outputs/tls-real32
python -m experiments.tls_experiment --condition tls12_gcm_randomized \
  --training-seed 32 --data data/recovery --prepared outputs/tls-inputs \
  --output outputs/tls-random32
```

Repeat the two commands for seeds 42 and 52 with distinct output paths. Both
conditions use model mode `real`; their scientific condition is recorded separately
in `run.json`. An OOM retry prevents recording a comparable TLS result. The public
entry points use the same scientific routines as the validated implementation;
old machine/archive-specific coordination and report templates remain recoverable
on the research branch.

## Checkpoints and historical evidence

Published metrics can always be checked from saved predictions without weights.
When the original ignored local checkpoints and graph caches are available:

```sh
python -m tests.verify_checkpoints
```

This loads all 15 multi-seed/TLS checkpoints strictly into both the frozen reference
and canonical model, compares logits exactly, and checks all held-out predictions
and metrics against saved records. It never trains or writes weights/caches.
Checkpoint files are intentionally not distributed.

The immutable research snapshot is commit
`121f48446611c35763a46c8b7546ee3c8543458c`, locally preserved as
`archive/research-full-2026-10-08`. Full original reports, pilot outputs,
software/resource metadata and preservation receipts are available through
`git show` or `git archive` at that commit. The source and result provenance
records retain the historical commit/path names; they have not been rewritten to
claim the public refactor produced the earlier results.
