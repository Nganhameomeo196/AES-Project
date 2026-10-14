"""
test_aes_nv1.py - Kiem thu NV1 Tuan 3 (AES Encryption / Decryption)
Chay:  python test_aes_nv1.py
Kiem thu tren chinh code cua nhom: key_expansion.py, aes_core.py, aes_encrypt.py, aes_decrypt.py
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
from key_expansion import SBOX, round_keys, _gmul
from aes_core import (bytes_to_state, state_to_bytes, state_hex, sub_bytes, inv_sub_bytes,
                      shift_rows, inv_shift_rows, mix_columns, inv_mix_columns, add_round_key,
                      INV_SBOX, _mix_column, _MIX)
from aes_encrypt import aes_encrypt
from aes_decrypt import aes_decrypt

H = bytes.fromhex
results = []


def check(name, ok):
    results.append((name, bool(ok)))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}")


# ---------------- Nhom 1: thanh phan ----------------
check("S-box: S(00)=63, S(53)=ED, S(A7)=5C, S(FF)=16",
      (SBOX[0x00], SBOX[0x53], SBOX[0xA7], SBOX[0xFF]) == (0x63, 0xED, 0x5C, 0x16))
check("InvSubBytes(SubBytes(s)) = s voi moi byte 00..FF", all(INV_SBOX[SBOX[x]] == x for x in range(256)))
check("GF(2^8): 57 x 83 = C1", _gmul(0x57, 0x83) == 0xC1)
check("MixColumns: DB 13 53 45 -> 8E 4D A1 BC", _mix_column([0xdb, 0x13, 0x53, 0x45], _MIX) == [0x8E, 0x4D, 0xA1, 0xBC])
check("MixColumns: 57 83 1B C6 -> ED A1 B3 F6", _mix_column([0x57, 0x83, 0x1B, 0xC6], _MIX) == [0xED, 0xA1, 0xB3, 0xF6])
s = bytes_to_state(os.urandom(16))
check("InvShiftRows(ShiftRows(s)) = s", inv_shift_rows(shift_rows(s)) == s)
check("InvMixColumns(MixColumns(s)) = s", inv_mix_columns(mix_columns(s)) == s)
check("State column-major: State[r][c] = block[4c+r]", bytes_to_state(bytes(range(16)))[1][2] == 9)
check("state_to_bytes(bytes_to_state(x)) = x", state_to_bytes(bytes_to_state(bytes(range(16)))) == bytes(range(16)))

# ---------------- Nhom 2: test vector FIPS-197 ----------------
VEC = [
    ("FIPS-197 App.B  AES-128", "2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
    ("FIPS-197 C.1    AES-128", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("FIPS-197 C.2    AES-192", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("FIPS-197 C.3    AES-256", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
]
for name, k, p, c in VEC:
    check(f"{name}: Encrypt -> {c}", aes_encrypt(H(p), H(k)).hex() == c)
    check(f"{name}: Decrypt -> {p}", aes_decrypt(H(c), H(k)).hex() == p)

# ---------------- Nhom 3: kiem tra tung round (AES-128, FIPS-197 C.1) ----------------
K, P = H("000102030405060708090a0b0c0d0e0f"), H("00112233445566778899aabbccddeeff")
rk = round_keys(K)
st = add_round_key(bytes_to_state(P), rk[0])
check("Initial Round: State XOR K0 = 00102030405060708090a0b0c0d0e0f0", state_hex(st) == "00102030405060708090a0b0c0d0e0f0")
st1 = sub_bytes(st);      check("Round 1 SubBytes   = 63cab7040953d051cd60e0e7ba70e18c", state_hex(st1) == "63cab7040953d051cd60e0e7ba70e18c")
st1 = shift_rows(st1);    check("Round 1 ShiftRows  = 6353e08c0960e104cd70b751bacad0e7", state_hex(st1) == "6353e08c0960e104cd70b751bacad0e7")
st1 = mix_columns(st1);   check("Round 1 MixColumns = 5f72641557f5bc92f7be3b291db9f91a", state_hex(st1) == "5f72641557f5bc92f7be3b291db9f91a")
st1 = add_round_key(st1, rk[1]); check("Round 1 AddRoundKey= 89d810e8855ace682d1843d8cb128fe4", state_hex(st1) == "89d810e8855ace682d1843d8cb128fe4")

# State sau tung round khi ma hoa (E[0..Nr]) va khi giai ma - doi chieu guong
def enc_states(pt, key):
    rks = round_keys(key); nr = len(rks) - 1
    E = {}; sr = {}
    s = add_round_key(bytes_to_state(pt), rks[0]); E[0] = state_hex(s)
    for r in range(1, nr):
        s = sub_bytes(s); s = shift_rows(s); sr[r] = state_hex(s)
        s = mix_columns(s); s = add_round_key(s, rks[r]); E[r] = state_hex(s)
    s = sub_bytes(s); s = shift_rows(s); sr[nr] = state_hex(s)
    s = add_round_key(s, rks[nr]); E[nr] = state_hex(s)
    return E, sr, nr

def dec_states(ct, key):
    rks = round_keys(key); nr = len(rks) - 1
    D = {}
    s = add_round_key(bytes_to_state(ct), rks[nr]); D["start"] = state_hex(s)
    for r in range(nr - 1, 0, -1):
        s = inv_shift_rows(s); s = inv_sub_bytes(s); D[f"isb{r}"] = state_hex(s)
        s = add_round_key(s, rks[r]); s = inv_mix_columns(s); D[f"im{r}"] = state_hex(s)
    s = inv_shift_rows(s); s = inv_sub_bytes(s); D["final_isb"] = state_hex(s)
    s = add_round_key(s, rks[0]); D["final"] = state_hex(s)
    return D

for name, k, p, c in VEC:
    E, sr, nr = enc_states(H(p), H(k))
    D = dec_states(H(c), H(k))
    ok = E[nr] == c and D["start"] == sr[nr]                 # AddRoundKey[Nr] huy K cuoi
    for r in range(nr - 1, 0, -1):
        ok &= D[f"isb{r}"] == E[r]                           # InvSubBytes khoi phuc state cuoi round r
        ok &= D[f"im{r}"] == sr[r]                           # InvMixColumns khoi phuc state sau ShiftRows round r
    ok &= D["final_isb"] == E[0] and D["final"] == p
    check(f"Doi chieu guong Encrypt<->Decrypt tung round ({name}, {nr} round)", ok)

# ---------------- Nhom 4: ngau nhien + tinh chat ----------------
n = 0
for klen in (16, 24, 32):
    for _ in range(300):
        key, pt = os.urandom(klen), os.urandom(16)
        n += aes_decrypt(aes_encrypt(pt, key), key) == pt
check("Round-trip Plaintext->Encrypt->Decrypt->Plaintext: 900/900 mau ngau nhien (AES-128/192/256)", n == 900)
w = bytearray(K); w[0] ^= 1
check("Giai ma bang key sai (lech 1 bit) khong ra Plaintext", aes_decrypt(aes_encrypt(P, K), bytes(w)) != P)
p2 = bytearray(P); p2[0] ^= 1
a, b = aes_encrypt(P, K), aes_encrypt(bytes(p2), K)
diff = bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")
check(f"Hieu ung lan truyen: doi 1 bit Plaintext -> {diff}/128 bit Ciphertext thay doi (ky vong ~64)", 40 <= diff <= 88)
check("Final Round khong co MixColumns: them MixColumns o round 10 se cho ket qua SAI",
      state_hex(add_round_key(mix_columns(shift_rows(sub_bytes(bytes_to_state(H(enc_states(P, K)[0][9]))))), rk[10])) != "69c4e0d86a7b0430d8cdb78070b4c55a")

print(f"\nTONG KET: {sum(ok for _, ok in results)}/{len(results)} test PASS")
try:
    aes_encrypt(bytes(15), bytes(16)); check("Block 15 byte bi tu choi", False)
except ValueError:
    check("Block 15 byte bi tu choi", True)
try:
    aes_encrypt(bytes(16), bytes(20)); check("Key 20 byte bi tu choi", False)
except ValueError:
    check("Key 20 byte bi tu choi", True)