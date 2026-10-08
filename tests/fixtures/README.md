# Regression references

`base_model.py` is byte-for-byte `src/model.py` from research commit
`121f48446611c35763a46c8b7546ee3c8543458c`. `validated_model.py` is that
commit's `recovery/model.py`, with only its path-injection/import block replaced
by a package import of `base_model`. These frozen test fixtures are never used
by training or experiments. They retain the upstream attribution in the repository
NOTICE and Apache-2.0 LICENSE.

`test_model_equivalence.py` compares them with the canonical `src.model.TFEGNN`.
It checks seeded state dictionaries and RNG state, evaluation logits, training
logits/gradients/BatchNorm updates, and strict state-dict loading. All comparisons
use exact tensor equality.

`scientific_kernels.json` records AST hashes for 41 original scientific
functions/classes. Only package paths and the equivalent canonical model call
were normalized when recording the references. The corresponding test guards
extraction, graph construction, grouping, training, metrics, TLS parsing and
randomization against unintended changes.
