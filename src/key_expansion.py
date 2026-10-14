from functools import lru_cache
# ---------- S-box (sinh tu GF(2^8), co the thay bang bang tra cua nhom) ----------
def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF
 
 
def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r
 
 
def _make_sbox():
    sbox = []
    for x in range(256):
        inv = 0
        if x:
            inv = next(y for y in range(1, 256) if _gmul(x, y) == 1)
        s = inv
        for i in range(1, 5):                      # affine transform
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    return sbox
 
 
SBOX = _make_sbox()
 
 
# ---------- Cac ham con ----------
def rot_word(w):
    return w[1:] + w[:1]                           # [a,b,c,d] -> [b,c,d,a]
 
 
def sub_word(w):
    return [SBOX[b] for b in w]
 
 
def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]
 
 
def make_rcon(n=10):
    rcon, r = [], 1
    for _ in range(n):
        rcon.append([r, 0, 0, 0])
        r = _xtime(r)
    return rcon                                    # rcon[0] ung voi Rcon[1]
 
 
# ---------- Key Expansion ----------
def key_expansion(key: bytes):
    if len(key) not in (16, 24, 32):
        raise ValueError("Key phai dai 16, 24 hoac 32 byte")
    nk = len(key) // 4
def key_expansion(key: bytes):
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nk = len(key) // 4                             # 4, 6, 8
    nr = nk + 6                                    # 10, 12, 14
    rcon = make_rcon()
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
 
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = xor_words(sub_word(rot_word(temp)), rcon[i // nk - 1])
        elif nk > 6 and i % nk == 4:               # chi AES-256
            temp = sub_word(temp)
        w.append(xor_words(w[i - nk], temp))
    return w                                       # round key r = w[4r : 4r+4]
 
 
@lru_cache(maxsize=256)
def _cached_round_keys(key: bytes):
    words = key_expansion(key)
    return tuple(tuple(sum(words[4*r:4*r+4], [])) for r in range(len(words)//4))


def round_keys(key: bytes):
    """Return independent mutable round-key lists; immutable schedules are cached."""
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    return [list(item) for item in _cached_round_keys(key)]
 
 
if __name__ == "__main__":
    tests = [
        ("AES-128", "2b7e151628aed2a6abf7158809cf4f3c",
         "d014f9a8c9ee2589e13f0cc8b6630ca6"),
        ("AES-192", "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
         "e98ba06f448c773c8ecc720401002202"),
        ("AES-256", "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
         "fe4890d1e6188d0b046df344706c631e"),
    ]
    for name, key, last in tests:
        rk = round_keys(bytes.fromhex(key))
        got = bytes(rk[-1]).hex()
        print(name, "OK" if got == last else "SAI", "-", len(rk), "round keys")
 

 