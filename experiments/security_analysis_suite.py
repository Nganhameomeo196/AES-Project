import os
import sys
import math
import random
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any

# Ensure stdout handles UTF-8 on Windows terminals
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.aes_encrypt import aes_encrypt
from src.aes_decrypt import aes_decrypt
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


def count_diff_bits(b1: bytes, b2: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(b1, b2))


# =========================================================================
# 1. THỰC NGHIỆM VÀ MÔ PHỎNG (EXPERIMENTS & SIMULATIONS)
# =========================================================================

def run_ecb_pattern_demo() -> Dict[str, Any]:
    """Khảo sát hiện tượng rò rỉ mẫu dữ liệu của chế độ ECB so với CBC."""
    key = bytes(range(16))
    iv = bytes(range(16))
    block_a = b"CONFIDENTIAL_16!"
    block_b = b"PUBLIC_HEADER16!"
    # 4 blocks: 1, 2, 4 identical; 3 different
    plaintext = block_a + block_a + block_b + block_a

    ct_ecb = ecb_encrypt(plaintext, key)[:64]
    ct_cbc = cbc_encrypt(plaintext, key, iv)[:64]

    ecb_blocks = [ct_ecb[i:i+16].hex() for i in range(0, 64, 16)]
    cbc_blocks = [ct_cbc[i:i+16].hex() for i in range(0, 64, 16)]

    ecb_leaked = (ecb_blocks[0] == ecb_blocks[1] == ecb_blocks[3])
    cbc_randomized = len(set(cbc_blocks)) == 4

    return {
        "ecb_blocks": ecb_blocks,
        "cbc_blocks": cbc_blocks,
        "ecb_leaked": ecb_leaked,
        "cbc_randomized": cbc_randomized
    }


def run_tampering_demo() -> Dict[str, Any]:
    """Khảo sát tính nhạy cảm và toàn vẹn khi sửa đổi 1 bit ciphertext giữa 4 chế độ."""
    key = bytes(range(16))
    iv = bytes(range(16))
    counter = bytes(range(16))
    nonce = bytes(range(12))
    aad = b"auth-header-2026"
    pt = b"Block01_16Bytes!" + b"Block02_16Bytes!" + b"Block03_16Bytes!"  # 48 bytes

    def flip_bit(data: bytes, byte_pos=16, bit_pos=0) -> bytes:
        arr = bytearray(data)
        arr[byte_pos] ^= (1 << bit_pos)
        return bytes(arr)

    # 1. ECB
    ct_ecb = ecb_encrypt(pt, key)
    dec_ecb = ecb_decrypt(flip_bit(ct_ecb), key)
    ecb_res = {
        "b1_intact": dec_ecb[:16] == pt[:16],
        "b2_corrupt": dec_ecb[16:32] != pt[16:32],
        "b3_intact": dec_ecb[32:48] == pt[32:48]
    }

    # 2. CBC
    ct_cbc = cbc_encrypt(pt, key, iv)
    dec_cbc = cbc_decrypt(flip_bit(ct_cbc), key, iv)
    cbc_res = {
        "b1_intact": dec_cbc[:16] == pt[:16],
        "b2_corrupt": dec_cbc[16:32] != pt[16:32],
        "b3_diff_bits": count_diff_bits(dec_cbc[32:48], pt[32:48]),
        "b3_plaintext": dec_cbc[32:48]
    }

    # 3. CTR
    ct_ctr = ctr_crypt(pt, key, counter)
    dec_ctr = ctr_crypt(flip_bit(ct_ctr), key, counter)
    ctr_res = {
        "diff_bits_total": count_diff_bits(dec_ctr, pt),
        "flipped_block": dec_ctr[16:32]
    }

    # 4. GCM
    ct_gcm, tag = gcm_encrypt(pt, key, nonce, aad)
    gcm_detected = False
    try:
        gcm_decrypt(flip_bit(ct_gcm), key, nonce, tag, aad)
    except ValueError:
        gcm_detected = True

    return {
        "ecb": ecb_res,
        "cbc": cbc_res,
        "ctr": ctr_res,
        "gcm_detected": gcm_detected
    }


def run_toy_bruteforce() -> Dict[str, Any]:
    """Mô phỏng vét cạn không gian khóa thu nhỏ 8-bit và đối chiếu 2^128."""
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    target_secret = 73
    target_key = bytes(15) + bytes([target_secret])
    ct = aes_encrypt(pt, target_key)

    t0 = time.perf_counter_ns()
    found_key = None
    trials = 0
    for cand in range(256):
        trials += 1
        if aes_encrypt(pt, bytes(15) + bytes([cand])) == ct:
            found_key = cand
            break
    elapsed_ms = (time.perf_counter_ns() - t0) / 1e6

    # Ước tính cho 2^128 với siêu máy tính (10^18 phép thử/giây)
    trials_per_sec_supercomputer = 1e18
    seconds_aes128 = (2**128) / trials_per_sec_supercomputer
    years_aes128 = seconds_aes128 / (365.25 * 86400)

    return {
        "found_key": found_key,
        "target_secret": target_secret,
        "trials": trials,
        "elapsed_ms": elapsed_ms,
        "years_aes128": years_aes128
    }


def run_avalanche_analysis() -> Dict[str, Any]:
    """Khảo sát chuẩn nghiêm ngặt Strict Avalanche Criterion (SAC ~ 50%)."""
    base_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    base_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    base_ct = aes_encrypt(base_pt, base_key)

    pt_diffs = []
    key_diffs = []

    for bit_idx in range(128):
        byte_pos = bit_idx // 8
        bit_pos = bit_idx % 8

        # Flip 1 bit Plaintext
        mod_pt = bytearray(base_pt)
        mod_pt[byte_pos] ^= (1 << bit_pos)
        ct_mod_pt = aes_encrypt(bytes(mod_pt), base_key)
        pt_diffs.append(count_diff_bits(base_ct, ct_mod_pt))

        # Flip 1 bit Key
        mod_key = bytearray(base_key)
        mod_key[byte_pos] ^= (1 << bit_pos)
        ct_mod_key = aes_encrypt(base_pt, bytes(mod_key))
        key_diffs.append(count_diff_bits(base_ct, ct_mod_key))

    avg_pt = sum(pt_diffs) / len(pt_diffs)
    avg_key = sum(key_diffs) / len(key_diffs)

    return {
        "pt_mean": avg_pt,
        "pt_pct": (avg_pt / 128) * 100,
        "pt_min": min(pt_diffs),
        "pt_max": max(pt_diffs),
        "key_mean": avg_key,
        "key_pct": (avg_key / 128) * 100,
        "key_min": min(key_diffs),
        "key_max": max(key_diffs)
    }


def run_cpa_simulation(samples=256, seed=2026) -> Dict[str, Any]:
    """Mô phỏng tấn công kênh kề Correlation Power Analysis (CPA)."""
    rng = random.Random(seed)
    secret_key_byte = 0xA7
    traces = []
    plaintexts = [rng.randrange(256) for _ in range(samples)]

    # Mô hình rò rỉ: Trọng số Hamming của SubBytes(pt ^ k) + nhiễu Gaussian
    for pt in plaintexts:
        hw = SBOX[pt ^ secret_key_byte].bit_count()
        noise = rng.gauss(0, 0.7)
        traces.append(hw + noise)

    def pearson_corr(x_list, y_list):
        n = len(x_list)
        mx = sum(x_list) / n
        my = sum(y_list) / n
        num = sum((x - mx) * (y - my) for x, y in zip(x_list, y_list))
        den = math.sqrt(sum((x - mx)**2 for x in x_list) * sum((y - my)**2 for y in y_list))
        return num / den if den != 0 else 0.0

    correlations = []
    for cand in range(256):
        hyp_hw = [SBOX[pt ^ cand].bit_count() for pt in plaintexts]
        r = pearson_corr(hyp_hw, traces)
        correlations.append((cand, r))

    best_candidate, best_corr = max(correlations, key=lambda item: abs(item[1]))
    success = (best_candidate == secret_key_byte)

    return {
        "secret_key_byte": f"0x{secret_key_byte:02X}",
        "recovered_byte": f"0x{best_candidate:02X}",
        "correlation": best_corr,
        "success": success
    }


def run_dfa_simulation() -> Dict[str, Any]:
    """Mô phỏng tấn công lỗi vi sai (Differential Fault Analysis - DFA) tại vòng 9."""
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes(range(16))

    # Mã hóa bình thường
    ct_correct = aes_encrypt(pt, key)

    # Mã hóa bị lỗi 1 byte tại vòng 9 trước MixColumns
    keys = round_keys(key)
    state = core.bytes_to_state(pt)
    state = core.add_round_key(state, keys[0])

    fault_round = 9
    for r in range(1, 11):
        state = core.sub_bytes(state)
        state = core.shift_rows(state)
        if r == fault_round:
            state[0][0] ^= 0x01  # Lỗi 1 bit tại 1 byte
        if r < 10:
            state = core.mix_columns(state)
        state = core.add_round_key(state, keys[r])

    ct_faulty = core.state_to_bytes(state)
    diff_bytes = sum(c1 != c2 for c1, c2 in zip(ct_correct, ct_faulty))

    return {
        "fault_round": 9,
        "fault_injected_bytes": 1,
        "ciphertext_corrupted_bytes": diff_bytes,
        "piret_quisquater_consistent": (diff_bytes == 4)
    }


def run_sbox_nonlinearity() -> Dict[str, Any]:
    """Đo đạc đặc tính phi tuyến của S-box: Bảng sai phân DDT."""
    ddt = [[0] * 256 for _ in range(256)]
    for delta_in in range(256):
        for x in range(256):
            delta_out = SBOX[x] ^ SBOX[x ^ delta_in]
            ddt[delta_in][delta_out] += 1

    max_ddt = max(max(row) for row in ddt[1:])

    return {
        "max_ddt": max_ddt,
        "ddt_probability": f"{max_ddt}/256 ({max_ddt/256:.4f})",
        "resistance": "Đạt chuẩn Rijndael tối ưu chống Phân tích Vi sai (Differential Cryptanalysis)"
    }



# =========================================================================
# 3. HÀM MAIN THỰC THI SUITE
# =========================================================================

def main():
    print("=================================================================")
    print("   AES PROJECT - BỘ CÔNG CỤ PHÂN TÍCH BẢO MẬT  ")
    print("=================================================================")

    print("\n[1/5] Đang chạy thực nghiệm ECB Pattern Leakage...")
    ecb_res = run_ecb_pattern_demo()
    print(f"      => Khối 1 == Khối 2 == Khối 4: {ecb_res['ecb_leaked']} (Rò rỉ 100%)")

    print("\n[2/5] Đang chạy thực nghiệm Tampering giữa 4 chế độ...")
    tamper_res = run_tampering_demo()
    print(f"      => GCM phát hiện sửa đổi & từ chối: {tamper_res['gcm_detected']}")

    print("\n[3/5] Đang chạy thực nghiệm Brute-Force không gian thu nhỏ...")
    bf_res = run_toy_bruteforce()
    print(f"      => Tìm thấy byte khóa bí mật {bf_res['found_key']} trong {bf_res['elapsed_ms']:.3f} ms.")

    print("\n[4/5] Đang chạy thực nghiệm Strict Avalanche Criterion...")
    avalanche_res = run_avalanche_analysis()
    print(f"      => Plaintext bit flip: {avalanche_res['pt_mean']:.2f}/128 ({avalanche_res['pt_pct']:.2f}%)")
    print(f"      => Key bit flip:       {avalanche_res['key_mean']:.2f}/128 ({avalanche_res['key_pct']:.2f}%)")

    print("\n[5/5] Đang chạy mô phỏng Tấn công Kênh kề (CPA) và Lỗi (DFA)...")
    cpa_res = run_cpa_simulation()
    print(f"      => CPA khôi phục byte khóa: {cpa_res['recovered_byte']} (Thành công: {cpa_res['success']})")
    dfa_res = run_dfa_simulation()
    print(f"      => DFA lỗi vòng 9 gây biến đổi: {dfa_res['ciphertext_corrupted_bytes']} byte ciphertext.")

    sbox_res = run_sbox_nonlinearity()

    metrics = {
        "ecb": ecb_res,
        "tamper": tamper_res,
        "bruteforce": bf_res,
        "avalanche": avalanche_res,
        "cpa": cpa_res,
        "dfa": dfa_res,
        "sbox": sbox_res
    }


if __name__ == "__main__":
    main()
