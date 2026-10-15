
from pathlib import Path

from src.modes import (
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    ctr_crypt, gcm_encrypt, gcm_decrypt
)

KEY = bytes(range(16))
IV = bytes(range(16))
COUNTER = bytes(range(16))
NONCE = bytes(range(12))
AAD = b"week4-header"

results = []


def log(message=""):
    print(message)
    results.append(message)


def check(name, condition):
    log(f"{name}: {'PASS' if condition else 'FAIL'}")


def test_roundtrip():
    log("\n=== 1. ENCRYPT / DECRYPT ===")

    cases = {
        "Short (5 bytes)": b"Hello",
        "Multiple blocks (48 bytes)": b"ABCDEFGHIJKLMNOP" * 3,
        "Not multiple of 16": b"AES modes test 12345",
    }

    for name, plaintext in cases.items():
        log(f"\nData: {name}")

        ct = ecb_encrypt(plaintext, KEY)
        check("ECB", ecb_decrypt(ct, KEY) == plaintext)

        ct = cbc_encrypt(plaintext, KEY, IV)
        check("CBC", cbc_decrypt(ct, KEY, IV) == plaintext)

        ct = ctr_crypt(plaintext, KEY, COUNTER)
        check("CTR", ctr_crypt(ct, KEY, COUNTER) == plaintext)

        ct, tag = gcm_encrypt(plaintext, KEY, NONCE, AAD)
        check(
            "GCM",
            gcm_decrypt(ct, KEY, NONCE, tag, AAD) == plaintext
        )


def test_iv_nonce():
    log("\n=== 2. IV / NONCE CHANGE ===")
    plaintext = b"Same plaintext"

    iv2 = bytes(range(1, 17))
    counter2 = bytes(range(1, 17))
    nonce2 = bytes(range(1, 13))

    check(
        "ECB same ciphertext",
        ecb_encrypt(plaintext, KEY) ==
        ecb_encrypt(plaintext, KEY)
    )

    check(
        "CBC ciphertext changes",
        cbc_encrypt(plaintext, KEY, IV) !=
        cbc_encrypt(plaintext, KEY, iv2)
    )

    check(
        "CTR ciphertext changes",
        ctr_crypt(plaintext, KEY, COUNTER) !=
        ctr_crypt(plaintext, KEY, counter2)
    )

    ct1, tag1 = gcm_encrypt(plaintext, KEY, NONCE)
    ct2, tag2 = gcm_encrypt(plaintext, KEY, nonce2)

    check("GCM ciphertext changes", ct1 != ct2)


def test_gcm_tamper():
    log("\n=== 3. GCM TAMPERING ===")
    plaintext = b"Secret AES message"

    ct, tag = gcm_encrypt(plaintext, KEY, NONCE, AAD)

    modified_ct = bytearray(ct)
    modified_ct[0] ^= 1

    modified_tag = bytearray(tag)
    modified_tag[0] ^= 1

    cases = [
        ("Modified ciphertext", bytes(modified_ct), tag, AAD),
        ("Modified tag", ct, bytes(modified_tag), AAD),
        ("Modified AAD", ct, tag, b"wrong-header"),
    ]

    for name, ciphertext, current_tag, aad in cases:
        try:
            gcm_decrypt(ciphertext, KEY, NONCE, current_tag, aad)
            log(f"{name}: FAIL")
        except ValueError:
            log(f"{name}: PASS (detected)")


def test_invalid():
    log("\n=== 4. INVALID INPUT ===")

    cases = [
        ("Invalid key",
         lambda: ecb_encrypt(b"Hello", b"short")),
        ("Invalid CBC IV",
         lambda: cbc_encrypt(b"Hello", KEY, b"bad")),
        ("Invalid CTR counter",
         lambda: ctr_crypt(b"Hello", KEY, b"bad")),
        ("Invalid ECB ciphertext",
         lambda: ecb_decrypt(b"abc", KEY)),
    ]

    for name, operation in cases:
        try:
            operation()
            log(f"{name}: FAIL")
        except ValueError:
            log(f"{name}: PASS (rejected)")


if __name__ == "__main__":
    test_roundtrip()
    test_iv_nonce()
    test_gcm_tamper()
    test_invalid()

    Path("results").mkdir(exist_ok=True)
    Path("results/week4_results.txt").write_text(
        "\n".join(results) + "\n",
        encoding="utf-8"
    )
    print("\nSaved: results/week4_results.txt")
