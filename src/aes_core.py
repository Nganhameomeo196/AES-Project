"""
AES core transforms: State, SubBytes, ShiftRows, MixColumns, AddRoundKey
va cac phep nghich dao - dung chung S-box/Rcon voi key_expansion.py
"""

from key_expansion import SBOX, _gmul

# ---------- Inverse S-box ----------
INV_SBOX = [0] * 256
for i, s in enumerate(SBOX):
    INV_SBOX[s] = i


# ---------- State: chuyen doi plaintext (16 byte) <-> ma tran 4x4 ----------
# Quy uoc cot: State[r][c] = P[4c + r]  (dung theo dac ta FIPS-197)
def bytes_to_state(data: bytes):
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        r, c = i % 4, i // 4
        state[r][c] = data[i]
    return state


def state_to_bytes(state) -> bytes:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[4 * c + r] = state[r][c]
    return bytes(out)


# ---------- SubBytes / InvSubBytes ----------
def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


# ---------- ShiftRows / InvShiftRows ----------
def shift_rows(state):
    # hang r dich trai r vi tri
    return [state[r][r:] + state[r][:r] for r in range(4)]


def inv_shift_rows(state):
    # hang r dich phai r vi tri
    return [state[r][-r:] + state[r][:-r] if r else state[r][:] for r in range(4)]


# ---------- MixColumns / InvMixColumns (GF(2^8)) ----------
_MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
_INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def _mix_column(col, matrix):
    return [
        _gmul(matrix[r][0], col[0]) ^ _gmul(matrix[r][1], col[1]) ^
        _gmul(matrix[r][2], col[2]) ^ _gmul(matrix[r][3], col[3])
        for r in range(4)
    ]


def mix_columns(state):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = _mix_column(col, _MIX)
        for r in range(4):
            new[r][c] = mixed[r]
    return new


def inv_mix_columns(state):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = _mix_column(col, _INV_MIX)
        for r in range(4):
            new[r][c] = mixed[r]
    return new


# ---------- AddRoundKey ----------
def add_round_key(state, round_key_bytes):
    rk_state = bytes_to_state(bytes(round_key_bytes))
    return [[state[r][c] ^ rk_state[r][c] for c in range(4)] for r in range(4)]


def state_hex(state) -> str:
    return state_to_bytes(state).hex()


if __name__ == "__main__":
    assert SBOX[0x53] == 0xED, "SubBytes 53 phai ra ED"
    assert INV_SBOX[0xED] == 0x53, "InvSubBytes phai la nghich dao dung"

    col = [0xdb, 0x13, 0x53, 0x45]
    mixed = _mix_column(col, _MIX)
    assert mixed == [0x8e, 0x4d, 0xa1, 0xbc], f"MixColumns sai: {[hex(x) for x in mixed]}"
    back = _mix_column(mixed, _INV_MIX)
    assert back == col, "InvMixColumns phai khoi phuc dung cot ban dau"

    s = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]]
    assert inv_shift_rows(shift_rows(s)) == s, "ShiftRows/InvShiftRows phai nghich dao nhau"

    print("Tat ca self-test aes_core.py: OK")