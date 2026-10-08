"""Pin the scientific routines to their validated syntax trees."""
import ast
import hashlib
import json
from pathlib import Path
import unittest


class ScientificKernelTests(unittest.TestCase):
    def test_validated_extraction_graph_split_training_and_intervention_routines(self):
        root = Path(__file__).resolve().parents[1]
        expected = json.loads((root / 'tests/fixtures/scientific_kernels.json').read_text())
        for row in expected['definitions']:
            with self.subTest(path=row['path'], definition=row['definition']):
                module = ast.parse((root / row['path']).read_text())
                node = next(n for n in module.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == row['definition'])
                digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                self.assertEqual(digest, row['ast_sha256'])
