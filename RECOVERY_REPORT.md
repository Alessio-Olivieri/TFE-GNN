# Recovery report — 7 October 2026

Inspection was read-only until the report was delivered in the conversation.

## Recovered state

- Repository: `TFE-GNN/`; its parent is not a Git repository.
- Origin: https://github.com/Alessio-Olivieri/TFE-GNN
- Branch: `master`; HEAD: `50eccea2aa9b0f76ac9b5c36039fe6a680265583`.
- One commit, authored by Alessio-Olivieri on 12 May 2026. Clean working tree;
  no modified, untracked, or ignored working files found.
- Python: `src/{config,dataset,model,paths,train,utils}.py`; also `test.ipynb`.
- Environment: `.python-version` requests 3.12; `pyproject.toml` and `uv.lock`
  describe PyTorch/PyG, NumPy, Scapy and scikit-learn. No `.venv` survived.
- README is empty. No generated NPZ/PT data, checkpoints, results or logs survived.
- `../ICSX-VPN` contains 31 files, approximately 2.4 GiB: Chat 10, Email 2,
  FileTransfer 6, P2P 1, Streaming 5, VoIP 7.
- Historical notebook paths refer to
  `/home/lexyo/Dev/reipmlementazione_classificazione_traffico_cifrato` and an old
  `dataset/Chat-20260505T092723Z-3-001/...` path. Those locations are absent.
- `src/paths.py` expects local `data`, `logs`, `checkpoints`, but no pipeline
  populates them. It also spells the checkpoints variable `chekpoints`.

## Evidence of progress and provenance

Saved notebook output shows successful Scapy PCAP-to-NPZ conversion and PyG graph
construction. There is no saved evidence of training or held-out evaluation.
One notebook calls `utils.construct_graph_pyg`, whereas the recovered function is
in `dataset.py`; the notebook records an earlier code state.

This is not a verbatim upstream checkout. The PyG encoder, batching, dataset
wrapper and Scapy extraction are substantial adaptations. The cross-gated fusion
is explicitly marked "Unchanged from original code" and closely follows upstream.
The LSTM/classification architecture and most configuration defaults also follow
upstream. A single commit cannot prove independent authorship or course compliance.
The student should explain and defend the adapted components and disclose the
upstream-derived components to the course supervisors.

Compared with original TFE-GNN (not CLE-TFE):

- Both use two byte-graph encoders, four mean-GraphSAGE layers, concatenated layer
  readouts, cross-gated fusion, and a two-layer bidirectional LSTM.
- Local dropout occurs after graph convolution and BN before PReLU; upstream DGL
  drops input features and applies PReLU before BN.
- Local preprocessing chunks captures in groups of 50 and rejects chunks below
  five packets. Upstream ISCX uses one sample per bidirectional TCP flow, retaining
  the first 50 packets, excluding flows with no payload or >10,000 data packets.
- Local preprocessing squares the PMI window (25 versus upstream 5).
- Local paired filtering removes empty-payload headers too; upstream independently
  retains all nonempty headers and all nonempty payloads.
- Local defaults use 14 classes; ISCX-VPN requires 6.
- Runtime blockers: nonexistent `torch.optim.GradualWarmupScheduler`,
  `WARM_UP_RATIO`, `PAYLOAD_MAX_LEN`, and `cfg.cfg`.
- Training examines the test set each epoch; no validation split or saved split
  manifest exists. This must be replaced before claiming controlled results.

Sources inspected: official repository https://github.com/ViktorAxelsen/TFE-GNN
(`model.py`, `config.py`, `utils.py`, `preprocess.py`, `pcap2npy.py`, `train.py`,
`dataloader.py`). Separate upstream reference HEAD:
`e62cb9f1e8b573ae962b0e605f50a1f0daeef1e2`.

## Dataset and machine findings

Packet inspection finds multiple TCP five-tuples and UDP in the capture files.
They need bidirectional flow extraction; class folders do not imply split flows.
Most files are classic PCAP with raw IPv4 link type 101; the VoipBuster files use
Ethernet. `vpn_hangouts_audio2.pcap` has PCAPNG magic despite its extension; it is
not established as corrupt by a classic-PCAP parser failing on it.

The six-class dataset cannot support three capture-disjoint partitions: P2P has
one capture and Email two. A flow-disjoint pilot sharing capture sources requires
an explicit methodological concession, and cannot establish generalization to
independent capture sources. Related a/b capture families may reduce independent
source counts further. No six-class results should be invented to bypass this.

Host read-only NVIDIA check: RTX A4000 Laptop GPU, 8192 MiB, driver 595.71.05.
System memory is approximately 30.6 GiB usable. The sandbox's failed NVIDIA check
was not host evidence; the elevated read-only check succeeded.

## Preservation and shortest route

Original files and Git metadata were archived to
`../recovery-backups/20261007T153459Z/TFE-GNN-original.tar.gz`, with SHA-256 hashes
in that directory. Backup branch `backup/recovered-20261007T153459Z` preserves the
original HEAD. Dataset files remain untouched. Original experimental files remain
intact; added recovery code reuses the model and graph constructor.

1. Set up an isolated Nix-compatible Python environment.
2. Extract TCP conversations; audit counts, duplicates and capture provenance.
3. Resolve the capture-isolation limitation; save reproducible shared split IDs.
4. Restore original model/preprocessing semantics while adapting the existing PyG
   implementation; validate extraction, graphs, ablations and batching.
5. Run real and random with identical split, initialization and training order,
   using validation only for checkpoint selection and test only for final metrics.
6. Record measured metrics and memory peaks. One seed is a pilot, not a conclusion.
