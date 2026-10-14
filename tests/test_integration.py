import unittest
from src.aes_encrypt import aes_encrypt
from src.aes_decrypt import aes_decrypt
from src.key_expansion import round_keys
from src import aes_modules, aes_core

PT = bytes.fromhex("00112233445566778899aabbccddeeff")
VECTORS = [
    (128, "69c4e0d86a7b0430d8cdb78070b4c55a"),
    (192, "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (256, "8ea2b7ca516745bfeafc49904b496089"),
]

class TestIntegration(unittest.TestCase):
    def test_known_answer_vectors_and_round_trip(self):
        for bits, expected in VECTORS:
            with self.subTest(bits=bits):
                key = bytes(range(bits // 8))
                ciphertext = aes_encrypt(PT, key)
                self.assertEqual(ciphertext.hex(), expected)
                self.assertEqual(aes_decrypt(bytes.fromhex(expected), key), PT)
                self.assertEqual(aes_decrypt(ciphertext, key), PT)
                self.assertEqual(len(round_keys(key)), {128: 11, 192: 13, 256: 15}[bits])

    def test_week2_modules_match_current_core(self):
        state = aes_core.bytes_to_state(PT)
        self.assertEqual(aes_modules.S_BOX, aes_core.SBOX)
        self.assertEqual(aes_modules.sub_bytes(state), aes_core.sub_bytes(state))
        self.assertEqual(aes_modules.shift_rows(state), aes_core.shift_rows(state))
        self.assertEqual(aes_modules.mix_columns(state), aes_core.mix_columns(state))
        key_state = aes_core.bytes_to_state(bytes(range(16)))
        self.assertEqual(aes_modules.add_round_key(state, key_state), aes_core.add_round_key(state, bytes(range(16))))

    def test_invalid_inputs(self):
        for size in (0, 15, 17):
            with self.assertRaises(ValueError):
                aes_encrypt(bytes(size), bytes(16))
            with self.assertRaises(ValueError):
                aes_decrypt(bytes(size), bytes(16))
        for size in (0, 15, 17, 31, 33):
            with self.assertRaises(ValueError):
                aes_encrypt(PT, bytes(size))
            with self.assertRaises(ValueError):
                aes_decrypt(PT, bytes(size))

if __name__ == "__main__":
    unittest.main()
