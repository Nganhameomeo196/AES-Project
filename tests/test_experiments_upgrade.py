"""Regression checks for visualization and fault propagation."""
import tempfile
import unittest
from pathlib import Path
from experiments.ecb_image import run as image_run
from experiments.fault_demo import encrypt_with_fault
from src.aes_encrypt import aes_encrypt
from src import aes_core


class ExperimentRegression(unittest.TestCase):
    def test_fault_propagation_four_bytes(self):
        pt = bytes.fromhex('00112233445566778899aabbccddeeff')
        key = bytes(range(16))
        correct = aes_encrypt(pt, key)
        self.assertEqual(encrypt_with_fault(pt, key, fault_round=-1), correct)
        faulted = encrypt_with_fault(pt, key)
        self.assertEqual(sum(a != b for a, b in zip(correct, faulted)), 4)

    def test_gf_table_matches_reference(self):
        for factor in (1, 2, 3, 9, 11, 13, 14):
            for byte in range(256):
                self.assertEqual(aes_core._GF_TABLE[factor][byte], aes_core._gmul(factor, byte))

    def test_png_export(self):
        with tempfile.TemporaryDirectory() as folder:
            image_run(width=16, height=16, output=folder)
            for name in ('original', 'ecb', 'cbc'):
                self.assertEqual((Path(folder) / f'pattern_{name}.png').read_bytes()[:8],
                                 b'\x89PNG\r\n\x1a\n')
