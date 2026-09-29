# tests/test_aes_modules.py

from src.aes_modules import (
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key
)


def print_state(title, state):
    print(f"\n{title}")

    for row in state:
        print(" ".join(f"{value:02x}" for value in row))


def check_test(test_name, actual, expected):
    print(f"\n===== {test_name} =====")

    print("Expected:")
    print_state("", expected)

    print("Actual:")
    print_state("", actual)

    if actual == expected:
        print(f"PASS: {test_name}")
        return True

    print(f"FAIL: {test_name}")
    return False


# ============================================================
# TEST DATA
# ============================================================

state = [
    [0x19, 0xa0, 0x9a, 0xe9],
    [0x3d, 0xf4, 0xc6, 0xf8],
    [0xe3, 0xe2, 0x8d, 0x48],
    [0xbe, 0x2b, 0x2a, 0x08]
]


# ============================================================
# 1. TEST SUBBYTES
# ============================================================

expected_sub_bytes = [
    [0xd4, 0xe0, 0xb8, 0x1e],
    [0x27, 0xbf, 0xb4, 0x41],
    [0x11, 0x98, 0x5d, 0x52],
    [0xae, 0xf1, 0xe5, 0x30]
]

actual_sub_bytes = sub_bytes(state)

sub_bytes_pass = check_test(
    "SubBytes",
    actual_sub_bytes,
    expected_sub_bytes
)


# ============================================================
# 2. TEST SHIFTROWS
# ============================================================

expected_shift_rows = [
    [0x19, 0xa0, 0x9a, 0xe9],
    [0xf4, 0xc6, 0xf8, 0x3d],
    [0x8d, 0x48, 0xe3, 0xe2],
    [0x08, 0xbe, 0x2b, 0x2a]
]

actual_shift_rows = shift_rows(state)

shift_rows_pass = check_test(
    "ShiftRows",
    actual_shift_rows,
    expected_shift_rows
)


# ============================================================
# 3. TEST MIXCOLUMNS
# ============================================================

# MixColumns được kiểm thử trên state sau ShiftRows.

shifted_state = expected_shift_rows

expected_mix_columns = [
    [0xb0, 0xfc, 0xf4, 0x46],
    [0x6e, 0x51, 0x64, 0x84],
    [0xf4, 0x2f, 0xc2, 0x75],
    [0x42, 0x12, 0xf8, 0xab]
]

actual_mix_columns = mix_columns(shifted_state)

mix_columns_pass = check_test(
    "MixColumns",
    actual_mix_columns,
    expected_mix_columns
)


# ============================================================
# 4. TEST ADDROUNDKEY
# ============================================================

round_key = [
    [0x2b, 0x28, 0xab, 0x09],
    [0x7e, 0xae, 0xf7, 0xcf],
    [0x15, 0xd2, 0x15, 0x4f],
    [0x16, 0xa6, 0x88, 0x3c]
]

expected_add_round_key = [
    [0x32, 0x88, 0x31, 0xe0],
    [0x43, 0x5a, 0x31, 0x37],
    [0xf6, 0x30, 0x98, 0x07],
    [0xa8, 0x8d, 0xa2, 0x34]
]

actual_add_round_key = add_round_key(
    state,
    round_key
)

add_round_key_pass = check_test(
    "AddRoundKey",
    actual_add_round_key,
    expected_add_round_key
)


# ============================================================
# SUMMARY
# ============================================================

all_tests = [
    sub_bytes_pass,
    shift_rows_pass,
    mix_columns_pass,
    add_round_key_pass
]

print("\n========================================")
print("TEST SUMMARY")
print("========================================")

print(f"SubBytes      : {'PASS' if sub_bytes_pass else 'FAIL'}")
print(f"ShiftRows     : {'PASS' if shift_rows_pass else 'FAIL'}")
print(f"MixColumns    : {'PASS' if mix_columns_pass else 'FAIL'}")
print(f"AddRoundKey   : {'PASS' if add_round_key_pass else 'FAIL'}")

if all(all_tests):
    print("\nALL TESTS PASSED")
else:
    print("\nSOME TESTS FAILED")