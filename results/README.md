# Published evidence

`payload_ablation/` holds the nine fixed-split payload runs;
`tls_ciphertext_ablation/` holds the six matched TLS/Real runs.

- `summary.csv`: means and sample SD across three training seeds.
- `all_runs.csv`: per-seed metrics and selected epochs.
- `paired_differences.csv`, `paired_summary.csv`: signed within-seed contrasts.
  Accuracy differences are proportions; multiply by 100 for percentage points.
- `runs.json`: original scientific fields, including labels, predictions, ordered
  sample IDs, class metrics, confusion matrices, epoch histories, seeds,
  hyperparameters, initialization hashes, source commits/hashes and limitations.
  Machine/resource logs, duplicate text and internal preservation receipts are
  omitted. Field values are unchanged; this is an explicit projection of the
  archived records, not regenerated experimental output.
- TLS `ciphertext_coverage.csv`: exact retained-byte accounting by class, split,
  protocol, capture and conservative acquisition group. Padding tokens are excluded.
- TLS `transformation.json` and `coverage_decision.json`: transformation identity,
  audited hashes and original pre-transformation scope decision. Paths in these
  original records refer to the archived experiment's layout.
- TLS `secondary_subset_accuracy.csv`: descriptive post-hoc affected/unaffected
  analysis; it does not replace evaluation on all 250 test samples.
- `capture_audit/`: final conservative capture groups, feasibility STOP,
  retained-layer/transport/stage counts and the source capture SHA-256 manifest.
- `splits-seed32.json`: byte-identical original sample IDs, grouping and indices.
- `provenance.json`: archived source paths/hashes, explicit projected fields and
  public-file hashes. All retained CSVs were copied byte-for-byte.

Source paths and commit hashes in original run records are historical provenance;
modules now live in `src/` and `experiments/`. The archive commit is
`121f48446611c35763a46c8b7546ee3c8543458c`. The omitted reports, full machine
metadata, internal receipts and preliminary pilot records remain on that commit.

Run `python -m experiments.verify_results` to recompute metrics from saved
predictions and validate summaries, paired differences, coverage, grouping,
fixed split membership and public artifact hashes. This command reads files only.
