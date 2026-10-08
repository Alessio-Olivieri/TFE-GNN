"""Compare canonical code with the frozen implementation used for the results."""
import unittest

import torch

from recovery.data import collate, padded_graphs
from src.model import TFEGNN
from tests.fixtures.validated_model import RecoveredTFEGNN


class ModelEquivalenceTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(2)
        self.batch = collate([
            (padded_graphs([[1, 2, 3, 1, 4]], 40),
             padded_graphs([[9, 8, 7, 9, 5]], 150), 0),
            (padded_graphs([[21, 22, 23]], 40),
             padded_graphs([[42, 43, 44, 45]], 150), 1),
        ])

    def pair(self, seed, mode):
        torch.manual_seed(seed)
        old = RecoveredTFEGNN(mode)
        old_rng = torch.get_rng_state()
        torch.manual_seed(seed)
        new = TFEGNN(payload_mode=mode)
        self.assertTrue(torch.equal(old_rng, torch.get_rng_state()))
        return old, new

    def test_initialized_parameters_buffers_keys_and_rng_exact(self):
        for seed in (32, 42, 52):
            with self.subTest(seed=seed):
                old, new = self.pair(seed, 'real')
                self.assertEqual(list(old.state_dict()), list(new.state_dict()))
                for key, value in old.state_dict().items():
                    self.assertTrue(torch.equal(value, new.state_dict()[key]), key)

    def test_eval_logits_exact_in_all_branch_modes(self):
        for mode in ('real', 'header-only', 'payload-only'):
            with self.subTest(mode=mode):
                old, new = self.pair(32, mode)
                old.eval()
                new.eval()
                with torch.no_grad():
                    self.assertTrue(torch.equal(old(*self.batch), new(*self.batch)))

    def test_training_dropout_logits_gradients_and_batchnorm_exact(self):
        for mode in ('real', 'header-only', 'payload-only'):
            with self.subTest(mode=mode):
                old, new = self.pair(32, mode)
                torch.manual_seed(123)
                a = old(*self.batch)
                a.sum().backward()
                torch.manual_seed(123)
                b = new(*self.batch)
                b.sum().backward()
                self.assertTrue(torch.equal(a, b))
                for (ka, pa), (kb, pb) in zip(old.named_parameters(), new.named_parameters()):
                    self.assertEqual(ka, kb)
                    if pa.grad is None:
                        self.assertIsNone(pb.grad, ka)
                    else:
                        self.assertTrue(torch.equal(pa.grad, pb.grad), ka)
                for key, value in old.state_dict().items():
                    self.assertTrue(torch.equal(value, new.state_dict()[key]), key)

    def test_strict_state_dict_loading_without_mapping(self):
        old, new = self.pair(42, 'real')
        new.load_state_dict(old.state_dict(), strict=True)
        old.eval()
        new.eval()
        with torch.no_grad():
            self.assertTrue(torch.equal(old(*self.batch), new(*self.batch)))
