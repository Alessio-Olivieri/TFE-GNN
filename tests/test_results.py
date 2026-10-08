"""Published evidence must remain internally consistent after reorganization."""
import unittest
from experiments.verify_results import verify


class PublishedResultsTests(unittest.TestCase):
    def test_saved_predictions_summaries_pairs_coverage_and_provenance(self):
        self.assertEqual(verify()['runs'], 15)
