"""Educational fault propagation: flip one state byte before round 9 MixColumns.

This is NOT a practical differential fault attack or a key recovery algorithm.
"""
import csv
from pathlib import Path
from src import aes_core as core
from src.key_expansion import round_keys


def encrypt_with_fault(plaintext: bytes, key: bytes, fault_round=9, fault_byte=0, mask=1):
    if len(plaintext) != 16 or len(key) not in (16, 24, 32):
        raise ValueError('Invalid AES block/key length')
    keys = round_keys(key)
    state = core.add_round_key(core.bytes_to_state(plaintext), keys[0])
    for round_number in range(1, len(keys)):
        state = core.sub_bytes(state)
        state = core.shift_rows(state)
        if round_number == fault_round:
            state[fault_byte % 4][fault_byte // 4] ^= mask
        if round_number < len(keys) - 1:
            state = core.mix_columns(state)
        state = core.add_round_key(state, keys[round_number])
    return core.state_to_bytes(state)


def run(output='results/fault_demo.csv'):
    pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    key = bytes(range(16))
    good = encrypt_with_fault(pt, key, fault_round=-1)
    bad = encrypt_with_fault(pt, key)
    rows = [{'position': i, 'correct': f'{a:02x}', 'faulted': f'{b:02x}', 'changed': int(a != b)}
            for i, (a, b) in enumerate(zip(good, bad))]
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f'Fault round 9: {sum(row["changed"] for row in rows)} changed ciphertext bytes')
    return rows


if __name__ == '__main__':
    run()
