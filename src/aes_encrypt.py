    # Initial Round
    # state = add_round_key(state, round_keys[0])

    # Main Rounds
    # for round_key in round_keys[1:-1]:
    #     state = sub_bytes(state)
    #     state = shift_rows(state)
    #     state = mix_columns(state)
    #     state = add_round_key(state, round_key)

    # Final Round
    # state = sub_bytes(state)
    # state = shift_rows(state)
    # state = add_round_key(state, round_keys[-1])

"""
AES Encrypt - rieng chieu ma hoa.

Cau truc:
    Initial AddRoundKey
    Main Rounds (1..Nr-1): SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    Final Round (Nr):      SubBytes -> ShiftRows -> AddRoundKey   (KHONG MixColumns)
"""

from key_expansion import round_keys
from aes_core import (
    bytes_to_state, state_to_bytes, sub_bytes,
    shift_rows, mix_columns, add_round_key, state_hex,
)


def aes_encrypt(plaintext: bytes, key: bytes, trace=False) -> bytes:
    rk = round_keys(key)          # rk[0..Nr], moi phan tu la list 16 byte
    nr = len(rk) - 1

    state = bytes_to_state(plaintext)

    # Initial Round
    state = add_round_key(state, rk[0])
    if trace:
        print(f"Sau Initial AddRoundKey : {state_hex(state)}")

    # Main Rounds
    for round_no in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, rk[round_no])
        if trace:
            print(f"Sau Round {round_no:>2}             : {state_hex(state)}")

    # Final Round: khong co MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, rk[nr])
    if trace:
        print(f"Sau Final Round ({nr})      : {state_hex(state)}")

    return state_to_bytes(state)


if __name__ == "__main__":
    # Test vector chuan FIPS-197
    tests = [
        ("AES-128", "000102030405060708090a0b0c0d0e0f",
         "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
         "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
    ]
    print("=== Kiem tra Encrypt voi test vector FIPS-197 ===\n")
    for name, key_hex, pt_hex, expected_ct_hex in tests:
        ct = aes_encrypt(bytes.fromhex(pt_hex), bytes.fromhex(key_hex))
        ok = ct.hex() == expected_ct_hex
        print(f"{name}: {'OK' if ok else 'SAI'}  ciphertext={ct.hex()}")

    print("\n=== Trace tung round - AES-128 ===")
    aes_encrypt(bytes.fromhex(tests[0][2]), bytes.fromhex(tests[0][1]), trace=True)