    # Initial Round
    # state = core.add_round_key(state, round_keys[0])

    # Main Rounds
    # for round_key in round_keys[1:-1]:
    #     state = core.sub_bytes(state)
    #     state = core.shift_rows(state)
    #     state = core.mix_columns(state)
    #     state = core.add_round_key(state, round_key)

    # Final Round
    # state = core.sub_bytes(state)
    # state = core.shift_rows(state)
    # state = core.add_round_key(state, round_keys[-1])

"""
AES Encrypt - rieng chieu ma hoa.

Cau truc:
    Initial AddRoundKey
    Main Rounds (1..Nr-1): SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    Final Round (Nr):      SubBytes -> ShiftRows -> AddRoundKey   (KHONG MixColumns)
"""

try:
    from .key_expansion import round_keys
    from . import aes_core as core
except ImportError:  # direct script execution
    from key_expansion import round_keys
    import aes_core as core



def aes_encrypt(plaintext: bytes, key: bytes, trace=False) -> bytes:
    if not isinstance(plaintext, bytes) or len(plaintext) != 16:
        raise ValueError("AES block must be exactly 16 bytes")
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    rk = round_keys(key)          # rk[0..Nr], moi phan tu la list 16 byte
    nr = len(rk) - 1

    state = core.bytes_to_state(plaintext)

    # Initial Round
    state = core.add_round_key(state, rk[0])
    if trace:
        print(f"Sau Initial AddRoundKey : {core.state_hex(state)}")

    # Main Rounds
    for round_no in range(1, nr):
        state = core.sub_bytes(state)
        state = core.shift_rows(state)
        state = core.mix_columns(state)
        state = core.add_round_key(state, rk[round_no])
        if trace:
            print(f"Sau Round {round_no:>2}             : {core.state_hex(state)}")

    # Final Round: khong co MixColumns
    state = core.sub_bytes(state)
    state = core.shift_rows(state)
    state = core.add_round_key(state, rk[nr])
    if trace:
        print(f"Sau Final Round ({nr})      : {core.state_hex(state)}")

    return core.state_to_bytes(state)


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