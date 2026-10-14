"""Week 2 AES transformation regression tests."""
import unittest
from src.aes_modules import sub_bytes, shift_rows, mix_columns, add_round_key

state = [[25, 160, 154, 233], [61, 244, 198, 248], [227, 226, 141, 72], [190, 43, 42, 8]]
expected_sub_bytes = [[212, 224, 184, 30], [39, 191, 180, 65], [17, 152, 93, 82], [174, 241, 229, 48]]
expected_shift_rows = [[25, 160, 154, 233], [244, 198, 248, 61], [141, 72, 227, 226], [8, 190, 43, 42]]
expected_mix_columns = [[176, 252, 244, 70], [110, 81, 100, 132], [244, 47, 194, 117], [66, 18, 248, 171]]
round_key = [[43, 40, 171, 9], [126, 174, 247, 207], [21, 210, 21, 79], [22, 166, 136, 60]]
expected_add_round_key = [[50, 136, 49, 224], [67, 90, 49, 55], [246, 48, 152, 7], [168, 141, 162, 52]]

class TestWeek2Modules(unittest.TestCase):
    def test_sub_bytes(self):
        self.assertEqual(sub_bytes(state), expected_sub_bytes)

    def test_shift_rows(self):
        self.assertEqual(shift_rows(state), expected_shift_rows)

    def test_mix_columns(self):
        self.assertEqual(mix_columns(expected_shift_rows), expected_mix_columns)

    def test_add_round_key(self):
        self.assertEqual(add_round_key(state, round_key), expected_add_round_key)

if __name__ == "__main__":
    unittest.main()
