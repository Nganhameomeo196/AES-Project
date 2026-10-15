
from src.modes import (
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    ctr_crypt,
    gcm_encrypt, gcm_decrypt
)

# Du lieu demo
KEY = bytes(range(16))
IV = bytes(range(16))
COUNTER = bytes(range(16))
NONCE = bytes(range(12))
AAD = b"week4-header"

PLAINTEXT = b"Hello AES Week 4!"


def show_result(mode, plaintext, ciphertext, decrypted, tag=None):
    print(f"\n===== AES-{mode} =====")
    print("Plaintext: ", plaintext.decode("utf-8"))
    print("Ciphertext (hex):", ciphertext.hex())

    if tag is not None:
        print("Authentication tag (hex):", tag.hex())

    print("Decrypted: ", decrypted.decode("utf-8"))
    print("Result:    ", "PASS" if decrypted == plaintext else "FAIL")


# 1. ECB
ct = ecb_encrypt(PLAINTEXT, KEY)
pt = ecb_decrypt(ct, KEY)
show_result("ECB", PLAINTEXT, ct, pt)

# 2. CBC
ct = cbc_encrypt(PLAINTEXT, KEY, IV)
pt = cbc_decrypt(ct, KEY, IV)
show_result("CBC", PLAINTEXT, ct, pt)

# 3. CTR
ct = ctr_crypt(PLAINTEXT, KEY, COUNTER)
pt = ctr_crypt(ct, KEY, COUNTER)
show_result("CTR", PLAINTEXT, ct, pt)

# 4. GCM
ct, tag = gcm_encrypt(PLAINTEXT, KEY, NONCE, AAD)
pt = gcm_decrypt(ct, KEY, NONCE, tag, AAD)
show_result("GCM", PLAINTEXT, ct, pt, tag)
