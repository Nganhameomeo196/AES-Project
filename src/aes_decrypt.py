"""
AES Decrypt - rieng chieu giai ma (dung thu tu nghich dao).

Cau truc:
    AddRoundKey (voi RoundKey[Nr])
    InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns   (lap Nr-1 .. 1)
    InvShiftRows -> InvSubBytes -> AddRoundKey (voi RoundKey[0])
"""

from key_expansion import round_keys
from aes_core import (
    bytes_to_state, state_to_bytes, inv_sub_bytes,
    inv_shift_rows, inv_mix_columns, add_round_key, state_hex,
)


def aes_decrypt(ciphertext: bytes, key: bytes, trace=False) -> bytes:
    rk = round_keys(key)
    nr = len(rk) - 1

    state = bytes_to_state(ciphertext)

    # Buoc dau: AddRoundKey voi RoundKey cuoi
    state = add_round_key(state, rk[nr])
    if trace:
        print(f"Sau AddRoundKey[{nr}]       : {state_hex(state)}")

    # Main Inverse Rounds
    for round_no in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, rk[round_no])
        state = inv_mix_columns(state)
        if trace:
            print(f"Sau Inv Round {round_no:>2}        : {state_hex(state)}")

    # Final Inverse Round: khong co InvMixColumns
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, rk[0])
    if trace:
        print(f"Sau AddRoundKey[0]       : {state_hex(state)}")

    return state_to_bytes(state)


if __name__ == "__main__":
    from aes_encrypt import aes_encrypt

    tests = [
        ("AES-128", "000102030405060708090a0b0c0d0e0f",
         "00112233445566778899aabbccddeeff"),
        ("AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617",
         "00112233445566778899aabbccddeeff"),
        ("AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "00112233445566778899aabbccddeeff"),
    ]
    print("=== Kiem tra Decrypt (round-trip Encrypt -> Decrypt) ===\n")
    for name, key_hex, pt_hex in tests:
        key = bytes.fromhex(key_hex)
        pt = bytes.fromhex(pt_hex)
        ct = aes_encrypt(pt, key)
        recovered = aes_decrypt(ct, key)
        ok = recovered == pt
        print(f"{name}: {'OK' if ok else 'SAI'}  decrypted={recovered.hex()}")

    print("\n=== Trace tung round - AES-128 ===")
    key128 = bytes.fromhex(tests[0][1])
    ct128 = aes_encrypt(bytes.fromhex(tests[0][2]), key128)
    aes_decrypt(ct128, key128, trace=True)