import os
from time import perf_counter_ns

try:
    import numpy as np
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

try:
    from src.aes_encrypt import aes_encrypt
    from src.modes import (
        ecb_encrypt, ecb_decrypt,
        cbc_encrypt, cbc_decrypt,
        ctr_crypt, gcm_encrypt, gcm_decrypt
    )
except ImportError:
    from aes_encrypt import aes_encrypt
    from modes import (
        ecb_encrypt, ecb_decrypt,
        cbc_encrypt, cbc_decrypt,
        ctr_crypt, gcm_encrypt, gcm_decrypt
    )

os.makedirs("results", exist_ok=True)
log_lines = []

def log(msg=""):
    print(msg)
    log_lines.append(msg)

def count_diff_bits(b1: bytes, b2: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(b1, b2))

# =========================================================================
# 1. DEMO ECB PATTERN LEAKAGE 
# =========================================================================
def demo_ecb_pattern():
    log("=================================================================")
    log("1. DEMO ECB PATTERN LEAKAGE (HIEN TUONG LO MAU DU LIEU)")
    log("=================================================================")
    key = bytes(range(16))
    iv = bytes(range(16))
    counter = bytes(range(16))
    nonce = bytes(range(12))

    # Tạo 4 khối 16 byte: Khối 1, 2, 4 giống hệt nhau ('A'*16), Khối 3 khác ('B'*16)
    block_a = b"A" * 16
    block_b = b"B" * 16
    plaintext = block_a + block_a + block_b + block_a

    ct_ecb = ecb_encrypt(plaintext, key)[:64]
    ct_cbc = cbc_encrypt(plaintext, key, iv)[:64]
    ct_ctr = ctr_crypt(plaintext, key, counter)[:64]
    ct_gcm, _ = gcm_encrypt(plaintext, key, nonce)

    ecb_blocks = [ct_ecb[i:i+16].hex() for i in range(0, 64, 16)]
    cbc_blocks = [ct_cbc[i:i+16].hex() for i in range(0, 64, 16)]
    ctr_blocks = [ct_ctr[i:i+16].hex() for i in range(0, 64, 16)]

    log("Plaintext (64 bytes = 4 blocks): Block 1 = Block 2 = Block 4 = 'A'*16, Block 3 = 'B'*16")
    log("\n[AES-ECB Ciphertext Blocks]:")
    for idx, b in enumerate(ecb_blocks, 1):
        log(f"  Block {idx}: {b}")
    is_leaked = (ecb_blocks[0] == ecb_blocks[1] == ecb_blocks[3])
    log(f"=> Kiem tra Block 1 == Block 2 == Block 4: {is_leaked} (LO MAU DU LIEU 100%!)")

    log("\n[AES-CBC Ciphertext Blocks]:")
    for idx, b in enumerate(cbc_blocks, 1):
        log(f"  Block {idx}: {b}")
    log("=> Ket luan CBC/CTR/GCM: Cac khoi ban ma khac nhau hoan toan nho IV/Counter.\n")

    if HAS_PLOT:
        img_grid = np.zeros((16, 16), dtype=np.uint8)
        img_grid[2:14, 2:14] = 200
        img_grid[5:11, 5:11] = 50
        raw_bytes = b"".join(bytes([int(val)] * 16) for val in img_grid.flatten())

        ecb_img_ct = ecb_encrypt(raw_bytes, key)[:len(raw_bytes)]
        cbc_img_ct = cbc_encrypt(raw_bytes, key, iv)[:len(raw_bytes)]

        ecb_vis = np.array([ecb_img_ct[i * 16] for i in range(256)]).reshape(16, 16)
        cbc_vis = np.array([cbc_img_ct[i * 16] for i in range(256)]).reshape(16, 16)

        fig, axes = plt.subplots(1, 3, figsize=(10, 3.5))
        axes[0].imshow(img_grid, cmap="gray")
        axes[0].set_title("Plaintext (Mau lap)")
        axes[1].imshow(ecb_vis, cmap="viridis")
        axes[1].set_title("AES-ECB (Lo ro cau truc)")
        axes[2].imshow(cbc_vis, cmap="viridis")
        axes[2].set_title("AES-CBC (Nhieu ngau nhien)")
        for ax in axes:
            ax.axis("off")
        plt.tight_layout()
        plt.savefig("results/ecb_pattern_demo.png", dpi=200)
        plt.close()

# =========================================================================
# 2. DEMO TAMPERING GIỮA 4 CHẾ ĐỘ 
# =========================================================================
def demo_tampering():
    log("=================================================================")
    log("2. DEMO TAMPERING (CHINH SUA 1 BIT CIPHERTEXT GIUA 4 MODE)")
    log("=================================================================")
    key = bytes(range(16))
    iv = bytes(range(16))
    counter = bytes(range(16))
    nonce = bytes(range(12))
    aad = b"header-auth"
    pt = b"Block01_16Bytes!" + b"Block02_16Bytes!" + b"Block03_16Bytes!"  # 48 bytes

    def flip_byte_16(data: bytes) -> bytes:
        arr = bytearray(data)
        arr[16] ^= 0x01  # Lật 1 bit đầu tiên của Block 2 (vị trí byte 16)
        return bytes(arr)

    # 1. ECB
    ct_ecb = flip_byte_16(ecb_encrypt(pt, key))
    dec_ecb = ecb_decrypt(ct_ecb, key)
    log(f"[ECB] Block 1 nguyen ven: {dec_ecb[:16]==pt[:16]} | Block 2 hong hoan toan: {dec_ecb[16:32]!=pt[16:32]} | Block 3 nguyen ven: {dec_ecb[32:48]==pt[32:48]}")

    # 2. CBC
    ct_cbc = flip_byte_16(cbc_encrypt(pt, key, iv))
    dec_cbc = cbc_decrypt(ct_cbc, key, iv)
    diff_b3_bytes = sum(x != y for x, y in zip(dec_cbc[32:48], pt[32:48]))
    diff_b3_bits = count_diff_bits(dec_cbc[32:48], pt[32:48])
    log(f"[CBC] Block 1 nguyen ven: {dec_cbc[:16]==pt[:16]} | Block 2 hong hoan toan | Block 3 bi lat dung {diff_b3_bytes} byte ({diff_b3_bits} bit): {dec_cbc[32:48]}")

    # 3. CTR
    ct_ctr = flip_byte_16(ctr_crypt(pt, key, counter))
    dec_ctr = ctr_crypt(ct_ctr, key, counter)
    diff_bits_ctr = count_diff_bits(dec_ctr, pt)
    log(f"[CTR] Khong bao loi! Toan bo plaintext chi bi lat dung {diff_bits_ctr} bit tai Block 2: {dec_ctr[16:32]}")

    # 4. GCM
    ct_gcm, tag = gcm_encrypt(pt, key, nonce, aad)
    ct_gcm_tampered = flip_byte_16(ct_gcm)
    try:
        gcm_decrypt(ct_gcm_tampered, key, nonce, tag, aad)
        log("[GCM] FAIL - Khong phat hien duoc chinh sua!")
    except ValueError:
        log("[GCM] PASS (Detected) - Phat hien chinh sua qua Authentication Tag va TU CHOI giai ma (ValueError)!\n")

# =========================================================================
# 3. DEMO BRUTE-FORCE SIMULATION 
# =========================================================================
def demo_bruteforce():
    log("=================================================================")
    log("3. BRUTE-FORCE SIMULATION (KHONG GIAN KHOA THU NHO 8-BIT = 256 KHOA)")
    log("=================================================================")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    secret_last_byte = 73
    true_key = bytes(15) + bytes([secret_last_byte])
    target_ct = aes_encrypt(pt, true_key)

    t0 = perf_counter_ns()
    found_byte = None
    for candidate in range(256):
        test_key = bytes(15) + bytes([candidate])
        if aes_encrypt(pt, test_key) == target_ct:
            found_byte = candidate
            break
    elapsed_ms = (perf_counter_ns() - t0) / 1e6
    log(f"Ket qua: Tim thay khoa byte cuoi = {found_byte} (sau {found_byte+1}/256 phep thu) trong {elapsed_ms:.3f} ms.")
    log("Danh gia: Voi AES-128 day du (2^128 = 3.4e38 khoa), vet can thong thuong la BAT KHA THI!\n")

# =========================================================================
# 4. PHÂN TÍCH AVALANCHE EFFECT 
# =========================================================================
def demo_avalanche():
    log("=================================================================")
    log("4. PHAN TICH AVALANCHE EFFECT (LAT TUNG BIT TRONG 128 BIT)")
    log("=================================================================")
    base_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    base_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    base_ct = aes_encrypt(base_pt, base_key)

    pt_diffs = []
    key_diffs = []

    for bit_idx in range(128):
        byte_pos = bit_idx // 8
        bit_pos = bit_idx % 8

        # 1. Lật 1 bit Plaintext
        mod_pt = bytearray(base_pt)
        mod_pt[byte_pos] ^= (1 << bit_pos)
        ct_mod_pt = aes_encrypt(bytes(mod_pt), base_key)
        pt_diffs.append(count_diff_bits(base_ct, ct_mod_pt))

        # 2. Lật 1 bit Key
        mod_key = bytearray(base_key)
        mod_key[byte_pos] ^= (1 << bit_pos)
        ct_mod_key = aes_encrypt(base_pt, bytes(mod_key))
        key_diffs.append(count_diff_bits(base_ct, ct_mod_key))

    avg_pt = sum(pt_diffs) / len(pt_diffs)
    avg_key = sum(key_diffs) / len(key_diffs)

    log(f"- Lat 1 bit Plaintext (128 vi tri): Bit dau = {pt_diffs[0]}/128 | Trung binh = {avg_pt:.2f}/128 bit ({avg_pt/128*100:.2f}%) | Min = {min(pt_diffs)}, Max = {max(pt_diffs)}")
    log(f"- Lat 1 bit Cipher Key (128 vi tri): Bit dau = {key_diffs[0]}/128 | Trung binh = {avg_key:.2f}/128 bit ({avg_key/128*100:.2f}%) | Min = {min(key_diffs)}, Max = {max(key_diffs)}")
    log("=> Dat chuan Strict Avalanche Criterion (SAC ~ 50% = 64/128 bit)!\n")

    if HAS_PLOT:
        plt.figure(figsize=(9, 4))
        plt.plot(range(1, 129), pt_diffs, label="Flip 1 bit Plaintext", color="#1f77b4", alpha=0.85)
        plt.plot(range(1, 129), key_diffs, label="Flip 1 bit Key", color="#ff7f0e", alpha=0.85)
        plt.axhline(64, color="red", linestyle="--", label="Ly tuong: 64/128 bit (50%)")
        plt.ylim(35, 95)
        plt.xlabel("Vi tri bit bi lat (1 -> 128)")
        plt.ylabel("So bit Ciphertext thay doi (/128 bit)")
        plt.title("Avalanche Effect tren AES-128 (Thay doi 1 bit Plaintext / Key)")
        plt.legend()
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.tight_layout()
        plt.savefig("results/avalanche_chart.png", dpi=200)
        plt.close()

if __name__ == "__main__":
    demo_ecb_pattern()
    demo_tampering()
    demo_bruteforce()
    demo_avalanche()
    with open("results/week4_security.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    print("Da luu log tai: results/week4_security.txt")
    if HAS_PLOT:
        print("Da luu 2 anh bieu do tai: results/ecb_pattern_demo.png va results/avalanche_chart.png")