"""Verify paired results and produce the preliminary supervisor handoff."""
import argparse
import json
from pathlib import Path

from recovery.audit import CLASSES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, default=Path('results'))
    parser.add_argument('--output', type=Path, default=Path('RESULTS_PRELIMINARY.md'))
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f'Refusing to overwrite {args.output}')
    real = json.loads((args.results / 'baseline.json').read_text())
    random = json.loads((args.results / f'random-seed{real["seed"]}.json').read_text())
    rows = [real, random]
    header_path = args.results / f'header-only-seed{real["seed"]}.json'
    if header_path.exists():
        rows.append(json.loads(header_path.read_text()))
    for result in rows:
        for key in ('seed', 'split_manifest_sha256', 'initial_state_sha256', 'preprocessing',
                    'hyperparameters', 'git_commit', 'source_sha256', 'batch_size', 'effective_batch_size'):
            if result[key] != real[key]:
                raise ValueError(f'Conditions differ in controlled setting: {key}')
        assert len(result['test_labels']) == result['split_sizes']['test']
        assert sum(map(sum, result['confusion_matrix'])) == result['split_sizes']['test']
        assert result['test_labels'] == real['test_labels']
        assert result['preliminary'] and not result['capture_disjoint']
    audit = json.loads(Path('data/recovery/audit.json').read_text())
    characterization_path = args.results / 'payload-characterization.json'
    characterization = json.loads(characterization_path.read_text()) if characterization_path.exists() else None
    out = ['# PRELIMINARY — original TFE-GNN payload ablation', '',
           'Prepared for discussion with Federica Bianchi and Prof. Angelo Spognardi.', '',
           '**This is a one-seed, flow-disjoint pilot. It is not capture-disjoint and may contain capture-level leakage. '
           'It does not establish final six-class scientific conclusions.**', '',
           '## What was run', '',
           f'Original TFE-GNN architecture adapted from the recovered PyTorch Geometric implementation, '
           f'seed {real["seed"]}, {real["hyperparameters"]["epochs"]} epochs per condition. '
           'No CLE-TFE changes. Hyperparameters were fixed before test evaluation; each model checkpoint was selected '
           'using validation macro F1 (validation loss breaks ties). Test was evaluated only after selection.', '',
           '## Exact dataset and preprocessing', '',
           f'Local `../ICSX-VPN`: {len(audit["captures"])} captures in six category folders, '
           f'{audit["total_samples"]} eligible flows. Capture paths, SHA-256 hashes, packet counts, link types and '
           'exclusions are recorded in `results/dataset-audit.json`. One `.pcap` file actually contains PCAPNG.', '',
           'TCP/IPv4 only. Extract bidirectional five-tuples within each capture; retain packet order and retransmissions, '
           'without TCP reassembly or idle timeout. Exclude empty-payload flows and flows with more than 10,000 data packets. '
           'Use the first 50 headers and independently the first 50 nonempty payloads per flow, matching upstream filtering. '
           'Remove IP addresses/TCP ports using actual header offsets; truncate to 40/150 bytes and pad with token 256. '
           'Positive-PMI graphs use window 5 and self loops. Constant inputs get singleton fallback graphs.', '',
           'Canonical TCP endpoint tuples and identical representations are grouped across captures using transitive closure. '
           'The same saved roughly 70/15/15 train/validation/test split is used for every condition. '
           'Capture sources are shared across partitions, as explicitly approved for this preliminary pilot. '
           'P2P has only one source capture and Email two, so the current collection cannot support three capture-disjoint partitions.', '',
           '| Class | Retained | Train | Validation | Test |',
           '|---|---:|---:|---:|---:|']
    for c in CLASSES:
        out.append(f'| {c} | {real["dataset_counts"][c]} | {real["split_counts"]["train"][c]} | '
                   f'{real["split_counts"]["validation"][c]} | {real["split_counts"]["test"][c]} |')
    out += [f'| Total | {sum(real["dataset_counts"].values())} | {real["split_sizes"]["train"]} | '
            f'{real["split_sizes"]["validation"]} | {real["split_sizes"]["test"]} |', '',
            '## Results', '', '| Condition | Seed | Accuracy | Macro precision | Macro recall | Macro F1 |',
            '|---|---:|---:|---:|---:|---:|']
    for r in rows:
        out.append(f'| {r["condition"]} | {r["seed"]} | {r["accuracy"]:.4f} | {r["macro_precision"]:.4f} | '
                   f'{r["macro_recall"]:.4f} | {r["macro_f1"]:.4f} |')
    difference = real['macro_f1'] - random['macro_f1']
    direction = 'higher' if difference > 0 else 'lower' if difference < 0 else 'equal'
    out += ['', f'Real payload macro F1 is {direction} than randomized payload in this single run '
            f'(real minus random: {difference:+.4f}). This is a descriptive paired result, not evidence of statistical significance '
            'or a general scientific conclusion.', '',
            '`random` generates seeded uniform bytes for each packet\'s exact original payload length BEFORE '
            'truncation, padding and payload graph construction. Headers (including original checksums), labels, packet order, '
            'flow order and split indices are unchanged. Payload RNG is independent of training RNG. '
            '`header-only` bypasses the payload encoder and provides a constant zero tensor to fusion. '
            '`zero` is available but replaces content with zero bytes while preserving length-dependent padding; '
            'it is not equivalent to strict header-only.', '', '## Important limitations', '',
            '- These are transport payload bytes, not a verified collection of pure ciphertext. TLS record framing, '
            'handshakes, plaintext protocol/control data and incidental background traffic can contribute signal. '
            'A real/random difference cannot isolate the contribution of cryptographic ciphertext.',
            '- Labels are inherited from capture folders; every incidental TCP conversation may not represent the '
            'named application category. Filtering very long flows can remove principal application traffic.',
            '- Sharing captures may expose capture-specific artifacts. Grouping prevents known duplicate/tuple leakage '
            'but cannot prove that all related sessions are identified.',
            '- One seed, a modest and imbalanced dataset, a changed split and a PyG port do not reproduce the paper\'s '
            'published benchmark numbers. No claim of independent-capture generalization is made.',
            '- Gradients accumulate to effective batch 32, but batch normalization uses the smaller physical minibatch. '
            'Dynamic header offsets, transport-level payload extraction and singleton graph fallback are documented '
            'implementation corrections rather than bit-identical upstream behavior.',
            '- Original header checksums remain unchanged under randomization. They can retain limited content-related '
            'information; rewriting them would violate the fixed-header control and requires a separate experiment.', '']
    if characterization:
        out += ['A prefix audit (heuristic, not protocol/decryption validation) found:', '',
                '| Class | Flows with TLS record prefix | Flows with HTTP method/response prefix | Flows with SSH banner |',
                '|---|---:|---:|---:|']
        for c in CLASSES:
            d = characterization['counts'][c]
            out.append(f'| {c} | {d["contains_tls_record_prefix"]} | {d["contains_http_method_or_response_prefix"]} | '
                       f'{d["contains_ssh_banner_prefix"]} |')
        out.append('')
    out += ['## Resources and reproducibility', '',
            '| Condition | Peak CUDA allocated MiB | Peak CUDA reserved MiB | Sampled GPU used MiB | Peak process-tree RSS MiB |',
            '|---|---:|---:|---:|---:|']
    for r in rows:
        d = r['resources']
        out.append(f'| {r["condition"]} | {d.get("peak_gpu_allocated_mib", 0):.0f} | '
                   f'{d.get("peak_gpu_reserved_mib", 0):.0f} | {d.get("peak_gpu_device_used_mib") or 0:.0f} | '
                   f'{d["peak_process_tree_rss_mib"]:.0f} |')
    out += ['', 'Graphs remain on disk/CPU; only the current minibatch is transferred to CUDA. '
            'RAM is sampled every 0.5 s and total device VRAM every 2 s; sampled peaks can miss short excursions. '
            'Tree RSS can double-count shared pages. Exact CUDA allocator peaks are reported separately.', '',
            f'- Training source commit: `{real["git_commit"]}`.',
            f'- Shared split fingerprint: `{real["split_manifest_sha256"]}`.',
            f'- Physical minibatch: {real["batch_size"]}; accumulation: {real["gradient_accumulation"]}; '
            f'effective batch: {real["effective_batch_size"]}.',
            '- Full metrics, per-class metrics, confusion matrices, selected epochs, training histories, commands, '
            'software/GPU versions, source hashes and memory measurements: `results/baseline.json` and condition JSON files.',
            '- Human-readable baseline: `results/baseline.txt`; table: `results/comparison.csv`; '
            'split indices and flow provenance: `results/splits-seed32.json`.', '',
            'Commands used:', '', '```sh', *[r['command'] for r in rows], '```', '',
            'Environment: `nix-shell recovery/shell.nix`. See `recovery/README.md` for setup, extraction and repeat-run commands.', '',
            '## Before drawing conclusions', '',
            'Repeat paired real/random/header-only conditions over multiple predeclared seeds, acquire enough independent '
            'capture sources for capture-disjoint training/validation/testing, validate application labels and encryption '
            'boundaries, and distinguish ciphertext from framing/handshake/plaintext signal. Report per-class effects and '
            'uncertainty over independent groups. Select hyperparameters using validation data only; reserve new independent '
            'test captures for the final protocol.', '',
            '## Recovery and course provenance', '',
            'The May 2026 PyG implementation and notebook remain byte-identical to the recovery snapshot. '
            'The original commit is preserved by a backup branch and archive. The recovery runner reuses the student\'s '
            'PyG model and graph constructor; fusion and architecture remain upstream-derived. Recovery changes were made '
            'with coding-assistant help. This report does not certify independent authorship or course compliance. '
            'See `RECOVERY_REPORT.md`.', '',
            'Official original TFE-GNN: https://github.com/ViktorAxelsen/TFE-GNN '
            '(reference commit `e62cb9f1e8b573ae962b0e605f50a1f0daeef1e2`).', '']
    with args.output.open('x') as f:
        f.write('\n'.join(out))
    print('Verified paired controls and wrote', args.output)


if __name__ == '__main__':
    main()
