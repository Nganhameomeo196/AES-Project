"""
AES Decrypt - rieng chieu giai ma (dung thu tu nghich dao).

Cau truc:
    AddRoundKey (voi RoundKey[Nr])
    InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns   (lap Nr-1 .. 1)
    InvShiftRows -> InvSubBytes -> AddRoundKey (voi RoundKey[0])
"""

try:
    from .key_expansion import round_keys
    from . import aes_core as core
except ImportError:  # direct script execution
    from key_expansion import round_keys
    import aes_core as core



def aes_decrypt(ciphertext: bytes, key: bytes, trace=False) -> bytes:
    if not isinstance(ciphertext, bytes) or len(ciphertext) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    rk = round_keys(key)
    nr = len(rk) - 1

    state = core.bytes_to_state(ciphertext)

    # Buoc dau: AddRoundKey voi RoundKey cuoi
    state = core.add_round_key(state, rk[nr])
    if trace:
        print(f"Sau AddRoundKey[{nr}]       : {core.state_hex(state)}")

    # Main Inverse Rounds
    for round_no in range(nr - 1, 0, -1):
        state = core.inv_shift_rows(state)
        state = core.inv_sub_bytes(state)
        state = core.add_round_key(state, rk[round_no])
        state = core.inv_mix_columns(state)
        if trace:
            print(f"Sau Inv Round {round_no:>2}        : {core.state_hex(state)}")

    # Final Inverse Round: khong co InvMixColumns
    state = core.inv_shift_rows(state)
    state = core.inv_sub_bytes(state)
    state = core.add_round_key(state, rk[0])
    if trace:
        print(f"Sau AddRoundKey[0]       : {core.state_hex(state)}")

    return core.state_to_bytes(state)


if __name__ == "__main__":
    try:
        from .aes_encrypt import aes_encrypt
    except ImportError:
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