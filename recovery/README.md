# Original TFE-GNN recovery runner

Run from the repository root. Original `src/`, notebook and dependency files are
preserved. This runner adapts their PyG graph constructor/model and restores
original TFE-GNN semantics. It contains no CLE-TFE changes.

## Environment and commands

```sh
nix-shell recovery/shell.nix
uv venv --python python3.12 .venv-recovery
uv pip install --python .venv-recovery/bin/python torch==2.7.1 -r recovery/requirements.txt --index-url https://pypi.org/simple
export CUBLAS_WORKSPACE_CONFIG=:4096:8 PYTHONHASHSEED=32
.venv-recovery/bin/python -m unittest recovery.test_recovery -v
python3 recovery/audit.py --data-root ../ICSX-VPN
.venv-recovery/bin/python -m recovery.run --payload-mode real --allow-shared-captures
.venv-recovery/bin/python -m recovery.run --payload-mode random --allow-shared-captures
.venv-recovery/bin/python -m recovery.run --payload-mode header-only --allow-shared-captures
```

The initial audit and environment already exist after recovery. Do not recreate
them unnecessarily. Audit refuses to overwrite its output. Each experiment also
refuses existing result, log or checkpoint files. For repeat runs, use distinct
`--results`, `--checkpoints`, and `--log-dir` locations. Every seed's saved manifest
must be shared across conditions. Freeze all settings before examining test results.

For environment recreation with the exact recorded transitive package versions,
use `uv pip install --python .venv-recovery/bin/python -r recovery/requirements-resolved.txt`.
The Python, CUDA, cuDNN, GPU driver and host versions used are also saved in each
result JSON. The Nix shell inherits the host's Nixpkgs rather than a dedicated
project flake lock.

## Data representation and splitting

- Read classic PCAP and PCAPNG based on magic, including mislabeled extensions.
- TCP/IPv4 only. Count excluded non-IP, UDP, fragments and truncated packets.
- One unordered pair of TCP endpoints per capture; retain both directions in
  capture order, without idle timeout. This follows five-tuple splitting, not TCP
  stream reassembly. Retransmissions are retained; port reuse is conservatively
  grouped. Initial/final partial connections can remain.
- Exclude empty-payload flows and flows with >10,000 nonempty payload packets.
  Do not split long conversations into multiple 50-packet samples.
- Retain first 50 headers including ACK-only packets and independently first 50
  nonempty payloads, matching upstream's two independently filtered sequences.
  They are not necessarily packet-aligned. Header extraction uses the full TCP
  transport header rather than Scapy's application-layer `Raw` heuristics.
- Remove IPv4 addresses and TCP ports using actual IPv4 header length. Preserve IP
  options, improving on upstream's fixed offset. Preserve all other header fields,
  including original checksums, lengths and sequence numbers. No recomputation of
  checksums after intervention, so headers remain byte-identical between conditions.
- Truncate to 40 header / 150 payload bytes, pad with token 256; pad sequences to
  50 graphs. PMI window 5; positive-PMI edges plus self loops. PMI magnitudes do
  not weight GraphSAGE, as in upstream. Existing fallback supplies singleton
  graphs for constant/padding inputs where upstream could construct empty graphs.
- Group canonical endpoint tuples AND identical preprocessed representations
  across captures, using transitive closure, before deterministic roughly
  70/15/15 stratified group allocation. Save indices, IDs, provenance and hashes.
- `--allow-shared-captures` explicitly enables the user-approved **PRELIMINARY
  flow-disjoint pilot**. It permits capture-level leakage. Without it, capture
  families are grouped too, and the current six-class dataset cannot be split.
- Same split manifest, architecture, initialization seed and minibatch ordering
  for every condition. Intervention RNG is separate from training RNG.

## Conditions

- `real`: original captured transport payload bytes, unchanged, then upstream
  truncation/padding/graph construction.
- `random`: generate uniformly random 0–255 bytes of each packet's full original
  payload length using a SHA-256-derived per-sample/per-packet seeded NumPy RNG;
  THEN truncate, pad and build the graph. No change to labels, header, packet/flow
  order, lengths, padding boundary or split. Raw bytes past the representation cap
  need not be stored for real; random generates full length before truncation.
- `zero`: fill each original-length payload with byte 0, then truncate/pad/build.
  This retains the payload branch and length-dependent padding topology. It is
  **not** a strict header-only condition.
- `header-only`: bypass payload encoder and give fusion a constant zero tensor.
  Headers/fusion/LSTM dimensions remain the same; learned fusion biases remain.
  This removes both payload content and payload graph length information.
- `payload-only`: optional reciprocal diagnostic bypassing the header encoder.

## Training and resources

Original widths: embedding 64, four GraphSAGE layers each 128, concatenate readouts,
cross-gated fusion, two-layer bidirectional LSTM hidden width 1024, six-way head.
Restore DGL input dropout, PReLU then BN, and Xavier/ReLU-gain SAGE initialization.
PyG and DGL are not asserted bit-for-bit identical implementations.

Predeclared settings: seed 32, 20 epochs, Adam LR 0.01 with 10% linear warmup then
cosine to 0.0001, no weight decay or label smoothing, float32. Select best epoch
using validation macro F1, tie-break validation loss. Evaluate test once afterward.
Minibatch 8, accumulation 4 (effective 32). BN operates on minibatches, a documented
departure from upstream batch 32. OOM restarts with half batch size and compensating
accumulation; architecture is never reduced automatically.

Graph preparation uses four CPU workers, disk caches and bounded CPU LRU caches.
Only minibatches go to CUDA. RAM is sampled every 0.5 seconds (process-tree RSS,
host used and host available); device VRAM every 2 seconds. CUDA allocator's exact
allocated/reserved peaks are also reported. Sampling can miss brief host/device
peaks; summed RSS can double-count shared memory. No whole-dataset GPU preload.

## Research limits

The local files contain TCP transport payloads, not independently verified pure
ciphertext. Payloads can include TLS record framing, handshakes, protocol control
data, plaintext and background traffic. A real/random difference alone therefore
does not prove that cryptographic ciphertext contributes classification signal.
The current class labels come from capture folders, including incidental flows.
The >10,000-data-packet exclusion removes some long primary application flows.

The pilot shares capture sources and uses one seed. Before scientific conclusions,
repeat paired conditions across seeds, obtain capture-disjoint data, validate flow
labels/encryption boundaries, examine class/background imbalance and quantify
uncertainty using independent groups rather than treating related flows as IID.

Upstream: https://github.com/ViktorAxelsen/TFE-GNN (Apache-2.0); recovered commit
`50eccea2aa9b0f76ac9b5c36039fe6a680265583`. See `RECOVERY_REPORT.md` for authorship
boundaries. Recovery code was added with coding-assistant help; this does not
establish that the course's independent-reimplementation requirement is satisfied.
