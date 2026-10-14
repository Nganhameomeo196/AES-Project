"""Run with: python -m src.main (from project root)."""
from .aes_encrypt import aes_encrypt
from .aes_decrypt import aes_decrypt

def main():
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    for bits in (128, 192, 256):
        key = bytes(range(bits // 8))
        ciphertext = aes_encrypt(plaintext, key)
        recovered = aes_decrypt(ciphertext, key)
        print(f"AES-{bits}: plaintext={plaintext.hex()}")
        print(f"         ciphertext={ciphertext.hex()}")
        print(f"         decrypted={recovered.hex()} | {'PASS' if recovered == plaintext else 'FAIL'}")

if __name__ == "__main__":
    main()
