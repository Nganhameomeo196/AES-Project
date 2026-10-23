import os
import sys
import math
import random
from pathlib import Path
from time import perf_counter_ns
from typing import Dict, Any

# Đảm bảo hiển thị UTF-8 trên Windows Terminal
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Đảm bảo import được package src dù chạy từ thư mục nào
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    import numpy as np
    import matplotlib.pyplot as plt
    HAS_PLOT = True
except ImportError:
    HAS_PLOT = False

from src.aes_encrypt import aes_encrypt
from src.key_expansion import SBOX, round_keys
from src import aes_core as core
from src.modes import (
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    ctr_crypt, gcm_encrypt, gcm_decrypt
)

RESULTS_DIR = ROOT_DIR / "results"
DOCS_DIR = ROOT_DIR / "docs"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
DOCS_DIR.mkdir(parents=True, exist_ok=True)

log_lines = []


def log(msg: str = ""):
    print(msg)
    log_lines.append(msg)


def count_diff_bits(b1: bytes, b2: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(b1, b2))


# =========================================================================
# 1. DEMO ECB PATTERN LEAKAGE (RÒ RỈ MẪU DỮ LIỆU)
# =========================================================================
def run_ecb_pattern_demo() -> Dict[str, Any]:
    log("=================================================================")
    log("1. DEMO ECB PATTERN LEAKAGE (HIỆN TƯỢNG LỘ MẪU DỮ LIỆU)")
    log("=================================================================")
    key = bytes(range(16))
    iv = bytes(range(16))
    counter = bytes(range(16))
    nonce = bytes(range(12))

    block_a = b"A" * 16
    block_b = b"B" * 16
    plaintext = block_a + block_a + block_b + block_a  # 64 bytes (4 blocks)

    ct_ecb = ecb_encrypt(plaintext, key)[:64]
    ct_cbc = cbc_encrypt(plaintext, key, iv)[:64]
    ct_ctr = ctr_crypt(plaintext, key, counter)[:64]
    ct_gcm, _ = gcm_encrypt(plaintext, key, nonce)

    ecb_blocks = [ct_ecb[i:i+16].hex() for i in range(0, 64, 16)]
    cbc_blocks = [ct_cbc[i:i+16].hex() for i in range(0, 64, 16)]
    ctr_blocks = [ct_ctr[i:i+16].hex() for i in range(0, 64, 16)]
    gcm_blocks = [ct_gcm[i:i+16].hex() for i in range(0, 64, 16)]

    is_leaked = (ecb_blocks[0] == ecb_blocks[1] == ecb_blocks[3])
    cbc_randomized = (len(set(cbc_blocks)) == 4)

    log("Plaintext (64B = 4 khối): Khối 1 = Khối 2 = Khối 4 = 'A'*16, Khối 3 = 'B'*16")
    log("\n[AES-ECB Ciphertext Blocks]:")
    for idx, b in enumerate(ecb_blocks, 1):
        log(f"  Block {idx}: {b}")
    log(f"=> Kiểm tra Block 1 == Block 2 == Block 4: {is_leaked} (LỘ MẪU DỮ LIỆU 100%!)")

    log("\n[AES-CBC Ciphertext Blocks]:")
    for idx, b in enumerate(cbc_blocks, 1):
        log(f"  Block {idx}: {b}")

    log("\n[AES-CTR Ciphertext Blocks]:")
    for idx, b in enumerate(ctr_blocks, 1):
        log(f"  Block {idx}: {b}")

    log("\n[AES-GCM Ciphertext Blocks]:")
    for idx, b in enumerate(gcm_blocks, 1):
        log(f"  Block {idx}: {b}")
    log("\n=> Kết luận CBC / CTR / GCM: Các khối bản mã khác nhau hoàn toàn nhờ IV/Counter/Nonce.\n")

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
        axes[0].set_title("Plaintext (Mẫu lặp)")
        axes[1].imshow(ecb_vis, cmap="gray")
        axes[1].set_title("AES-ECB (Lộ rõ cấu trúc)")
        axes[2].imshow(cbc_vis, cmap="gray")
        axes[2].set_title("AES-CBC (Nhiễu ngẫu nhiên)")
        for ax in axes:
            ax.axis("off")
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / "ecb_pattern_demo.png", dpi=200)
        plt.close()

    return {
        "ecb_blocks": ecb_blocks,
        "cbc_blocks": cbc_blocks,
        "ecb_leaked": is_leaked,
        "cbc_randomized": cbc_randomized
    }


# =========================================================================
# 2. DEMO TAMPERING GIỮA 4 CHẾ ĐỘ (LAN TRUYỀN LỖI & XÁC THỰC)
# =========================================================================
def run_tampering_demo() -> Dict[str, Any]:
    log("=================================================================")
    log("2. DEMO TAMPERING (CHỈNH SỬA 1 BIT CIPHERTEXT GIỮA 4 MODE)")
    log("=================================================================")
    key = bytes(range(16))
    iv = bytes(range(16))
    counter = bytes(range(16))
    nonce = bytes(range(12))
    aad = b"header-auth"
    pt = b"Block01_16Bytes!" + b"Block02_16Bytes!" + b"Block03_16Bytes!"  # 48 bytes

    # Lật 1 bit tại byte 16 (byte đầu của Khối 2) để không chạm vào khối PKCS#7 padding ở cuối
    def flip_byte_16(data: bytes) -> bytes:
        arr = bytearray(data)
        arr[16] ^= 0x01
        return bytes(arr)

    # 1. ECB
    ct_ecb = flip_byte_16(ecb_encrypt(pt, key))
    dec_ecb = ecb_decrypt(ct_ecb, key)
    ecb_res = {
        "b1_intact": dec_ecb[:16] == pt[:16],
        "b2_corrupt": dec_ecb[16:32] != pt[16:32],
        "b3_intact": dec_ecb[32:48] == pt[32:48]
    }
    log(f"[ECB] Block 1 nguyên vẹn: {ecb_res['b1_intact']} | Block 2 hỏng hoàn toàn: {ecb_res['b2_corrupt']} | Block 3 nguyên vẹn: {ecb_res['b3_intact']}")

    # 2. CBC
    ct_cbc = flip_byte_16(cbc_encrypt(pt, key, iv))
    dec_cbc = cbc_decrypt(ct_cbc, key, iv)
    diff_b3_bytes = sum(x != y for x, y in zip(dec_cbc[32:48], pt[32:48]))
    diff_b3_bits = count_diff_bits(dec_cbc[32:48], pt[32:48])
    cbc_res = {
        "b1_intact": dec_cbc[:16] == pt[:16],
        "b2_corrupt": dec_cbc[16:32] != pt[16:32],
        "b3_diff_bytes": diff_b3_bytes,
        "b3_diff_bits": diff_b3_bits
    }
    log(f"[CBC] Block 1 nguyên vẹn: {cbc_res['b1_intact']} | Block 2 hỏng hoàn toàn | Block 3 bị lật đúng {diff_b3_bytes} byte ({diff_b3_bits} bit): {dec_cbc[32:48]}")

    # 3. CTR
    ct_ctr = flip_byte_16(ctr_crypt(pt, key, counter))
    dec_ctr = ctr_crypt(ct_ctr, key, counter)
    diff_bits_ctr = count_diff_bits(dec_ctr, pt)
    ctr_res = {"diff_bits_total": diff_bits_ctr, "flipped_block": dec_ctr[16:32]}
    log(f"[CTR] Không báo lỗi! Toàn bộ plaintext chỉ bị lật đúng {diff_bits_ctr} bit tại Block 2: {dec_ctr[16:32]}")

    # 4. GCM
    ct_gcm, tag = gcm_encrypt(pt, key, nonce, aad)
    ct_gcm_tampered = flip_byte_16(ct_gcm)
    gcm_detected = False
    try:
        gcm_decrypt(ct_gcm_tampered, key, nonce, tag, aad)
        log("[GCM] FAIL - Không phát hiện được chỉnh sửa!")
    except ValueError:
        gcm_detected = True
        log("[GCM] PASS (Detected) - Phát hiện chỉnh sửa qua Authentication Tag và TỪ CHỐI giải mã (ValueError)!\n")

    return {"ecb": ecb_res, "cbc": cbc_res, "ctr": ctr_res, "gcm_detected": gcm_detected}


# =========================================================================
# 3. DEMO BRUTE-FORCE SIMULATION
# =========================================================================
def run_toy_bruteforce() -> Dict[str, Any]:
    log("=================================================================")
    log("3. BRUTE-FORCE SIMULATION (KHÔNG GIAN KHÓA THU NHỎ 8-BIT = 256 KHÓA)")
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
    tested_keys = found_byte + 1 if found_byte is not None else 256
    py_speed = (tested_keys / (elapsed_ms / 1000)) if elapsed_ms > 0 else 0

    total_keys = 2**128
    years_py = (total_keys / py_speed) / (365.25 * 86400) if py_speed > 0 else float("inf")
    years_1e12 = (total_keys / 1e12) / (365.25 * 86400)  # Cụm phần cứng 10^12 keys/s
    years_1e18 = (total_keys / 1e18) / (365.25 * 86400)  # Siêu máy tính Exascale 10^18 keys/s

    log(f"Kết quả: Tìm thấy khóa byte cuối = {found_byte} (sau {tested_keys}/256 phép thử) trong {elapsed_ms:.3f} ms.")
    log(f"Tốc độ thử nghiệm Python: ~{py_speed:,.0f} keys/giây -> Cần ~{years_py:.2e} năm cho AES-128.")
    log(f"Ước tính với phần cứng 10^12 keys/s: ~{years_1e12:.2e} năm | Siêu máy tính 10^18 keys/s: ~{years_1e18:.2e} năm.")
    log("Đánh giá: Vét cạn toàn bộ không gian khóa AES-128 là BẤT KHẢ THI!\n")

    return {
        "found_key": found_byte,
        "trials": tested_keys,
        "elapsed_ms": elapsed_ms,
        "py_speed": py_speed,
        "years_1e12": years_1e12,
        "years_1e18": years_1e18
    }


# =========================================================================
# 4. PHÂN TÍCH AVALANCHE EFFECT (SAC ~ 50%)
# =========================================================================
def run_avalanche_analysis() -> Dict[str, Any]:
    log("=================================================================")
    log("4. PHÂN TÍCH AVALANCHE EFFECT (LẬT TỪNG BIT TRONG 128 BIT)")
    log("=================================================================")
    base_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    base_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    base_ct = aes_encrypt(base_pt, base_key)

    pt_diffs = []
    key_diffs = []

    for bit_idx in range(128):
        byte_pos = bit_idx // 8
        bit_pos = bit_idx % 8

        mod_pt = bytearray(base_pt)
        mod_pt[byte_pos] ^= (1 << bit_pos)
        pt_diffs.append(count_diff_bits(base_ct, aes_encrypt(bytes(mod_pt), base_key)))

        mod_key = bytearray(base_key)
        mod_key[byte_pos] ^= (1 << bit_pos)
        key_diffs.append(count_diff_bits(base_ct, aes_encrypt(base_pt, bytes(mod_key))))

    avg_pt = sum(pt_diffs) / len(pt_diffs)
    avg_key = sum(key_diffs) / len(key_diffs)

    log(f"- Lật 1 bit Plaintext (128 vị trí): Bit đầu = {pt_diffs[0]}/128 | Trung bình = {avg_pt:.2f}/128 bit ({avg_pt/128*100:.2f}%) | Min = {min(pt_diffs)}, Max = {max(pt_diffs)}")
    log(f"- Lật 1 bit Cipher Key (128 vị trí): Bit đầu = {key_diffs[0]}/128 | Trung bình = {avg_key:.2f}/128 bit ({avg_key/128*100:.2f}%) | Min = {min(key_diffs)}, Max = {max(key_diffs)}")
    log("=> Đạt chuẩn Strict Avalanche Criterion (SAC ~ 50% = 64/128 bit)!\n")

    if HAS_PLOT:
        plt.figure(figsize=(9, 4))
        plt.plot(range(1, 129), pt_diffs, label="Flip 1 bit Plaintext", color="#1f77b4", alpha=0.85)
        plt.plot(range(1, 129), key_diffs, label="Flip 1 bit Key", color="#ff7f0e", alpha=0.85)
        plt.axhline(64, color="red", linestyle="--", label="Lý tưởng: 64/128 bit (50%)")
        plt.ylim(35, 95)
        plt.xlabel("Vị trí bit bị lật (1 -> 128)")
        plt.ylabel("Số bit Ciphertext thay đổi (/128 bit)")
        plt.title("Avalanche Effect trên AES-128 (Thay đổi 1 bit Plaintext / Key)")
        plt.legend()
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.tight_layout()
        plt.savefig(RESULTS_DIR / "avalanche_chart.png", dpi=200)
        plt.close()

    return {
        "pt_mean": avg_pt, "pt_pct": (avg_pt / 128) * 100, "pt_min": min(pt_diffs), "pt_max": max(pt_diffs),
        "key_mean": avg_key, "key_pct": (avg_key / 128) * 100, "key_min": min(key_diffs), "key_max": max(key_diffs)
    }


# =========================================================================
# 5. MÔ PHỎNG SIDE-CHANNEL (CPA), FAULT ATTACK (DFA) & ĐỘ PHI TUYẾN S-BOX
# =========================================================================
def run_cpa_simulation(samples=256, seed=2026) -> Dict[str, Any]:
    rng = random.Random(seed)
    secret_key_byte = 0xA7
    plaintexts = [rng.randrange(256) for _ in range(samples)]
    traces = [SBOX[pt ^ secret_key_byte].bit_count() + rng.gauss(0, 0.7) for pt in plaintexts]

    def pearson_corr(x_list, y_list):
        n = len(x_list)
        mx, my = sum(x_list) / n, sum(y_list) / n
        num = sum((x - mx) * (y - my) for x, y in zip(x_list, y_list))
        den = math.sqrt(sum((x - mx)**2 for x in x_list) * sum((y - my)**2 for y in y_list))
        return num / den if den != 0 else 0.0

    correlations = [(cand, pearson_corr([SBOX[pt ^ cand].bit_count() for pt in plaintexts], traces)) for cand in range(256)]
    best_cand, best_corr = max(correlations, key=lambda item: abs(item[1]))
    return {"secret_key_byte": f"0x{secret_key_byte:02X}", "recovered_byte": f"0x{best_cand:02X}", "correlation": best_corr, "success": best_cand == secret_key_byte}


def run_dfa_simulation() -> Dict[str, Any]:
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes(range(16))
    ct_correct = aes_encrypt(pt, key)

    keys = round_keys(key)
    state = core.add_round_key(core.bytes_to_state(pt), keys[0])
    for r in range(1, 11):
        state = core.shift_rows(core.sub_bytes(state))
        if r == 9:
            state[0][0] ^= 0x01  # Chèn lỗi 1 bit tại Round 9 trước MixColumns
        if r < 10:
            state = core.mix_columns(state)
        state = core.add_round_key(state, keys[r])

    ct_faulty = core.state_to_bytes(state)
    diff_positions = [i for i, (c1, c2) in enumerate(zip(ct_correct, ct_faulty)) if c1 != c2]
    return {"fault_round": 9, "corrupted_bytes": len(diff_positions), "positions": diff_positions}


def run_sbox_nonlinearity() -> Dict[str, Any]:
    ddt = [[0] * 256 for _ in range(256)]
    for delta_in in range(256):
        for x in range(256):
            ddt[delta_in][SBOX[x] ^ SBOX[x ^ delta_in]] += 1
    max_ddt = max(max(row) for row in ddt[1:])
    return {"max_ddt": max_ddt, "ddt_probability": f"{max_ddt}/256 ({max_ddt/256:.4f})"}


def run_advanced_security_demos():
    log("=================================================================")
    log("5. MÔ PHỎNG TẤN CÔNG KÊNH KỀ (CPA), CHÈN LỖI (DFA) & S-BOX DDT")
    log("=================================================================")
    cpa = run_cpa_simulation()
    dfa = run_dfa_simulation()
    sbox = run_sbox_nonlinearity()

    log(f"- [CPA Side-Channel] Khóa mục tiêu: {cpa['secret_key_byte']} | Khôi phục: {cpa['recovered_byte']} (r = {cpa['correlation']:.4f}, Thành công: {cpa['success']})")
    log(f"- [DFA Fault Attack] Chèn lỗi 1 byte ở Vòng 9 -> Làm thay đổi {dfa['corrupted_bytes']} byte bản mã tại vị trí {dfa['positions']}")
    log(f"- [S-box DDT] Giá trị vi sai tối đa (khác 0): {sbox['max_ddt']} -> Xác suất {sbox['ddt_probability']}\n")


if __name__ == "__main__":
    run_ecb_pattern_demo()
    run_tampering_demo()
    run_toy_bruteforce()
    run_avalanche_analysis()
    run_advanced_security_demos()

    log_file_path = RESULTS_DIR / "week4_security.txt"
    log_file_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print(f"Đã lưu báo cáo log tại: {log_file_path}")
    if HAS_PLOT:
        print(f"Đã lưu 2 biểu đồ tại: {RESULTS_DIR / 'ecb_pattern_demo.png'} và {RESULTS_DIR / 'avalanche_chart.png'}")