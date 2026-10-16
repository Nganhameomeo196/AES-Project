
"""Educational related-key demonstration using AES-128.

This demonstrates relationships between two keys and their ciphertexts.
It is NOT a successful related-key attack against AES.
"""

from src.aes_encrypt import aes_encrypt


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    plaintext = b"HELLO AES DEMO!!"  # 16 bytes

    key1 = bytes(range(16))
    delta_key = bytes([0] * 15 + [1])
    key2 = xor_bytes(key1, delta_key)

    ciphertext1 = aes_encrypt(plaintext, key1)
    ciphertext2 = aes_encrypt(plaintext, key2)

    delta_ciphertext = xor_bytes(ciphertext1, ciphertext2)

    print("=== RELATED-KEY CRYPTANALYSIS DEMO ===")
    print("Plaintext     :", plaintext.hex())
    print("Key 1         :", key1.hex())
    print("Key 2         :", key2.hex())
    print("Delta Key     :", delta_key.hex())
    print("Ciphertext 1  :", ciphertext1.hex())
    print("Ciphertext 2  :", ciphertext2.hex())
    print("Delta Cipher  :", delta_ciphertext.hex())

    changed_bits = sum(
        byte.bit_count() for byte in delta_ciphertext
    )

    print("Different ciphertext bits:", changed_bits, "/ 128")
    print("Conclusion: Related keys produce different AES ciphertexts.")
    print("This is an illustration, NOT a key-recovery attack.")


if __name__ == "__main__":
    main()
