"""Trace AES internal states without printing or changing existing block APIs."""
from . import aes_core as c
from .key_expansion import round_keys

def encrypt_trace(block: bytes, key: bytes):
    if not isinstance(block, bytes) or len(block) != 16: raise ValueError("Block must be 16 bytes")
    keys = round_keys(key)
    state = c.bytes_to_state(block)
    events = []
    def emit(r, step): events.append({"round": r, "step": step, "state": c.state_hex(state)})
    emit(0, "input")
    state = c.add_round_key(state, keys[0]); emit(0, "AddRoundKey")
    for r in range(1, len(keys)):
        state = c.sub_bytes(state); emit(r, "SubBytes")
        state = c.shift_rows(state); emit(r, "ShiftRows")
        if r != len(keys)-1:
            state = c.mix_columns(state); emit(r, "MixColumns")
        state = c.add_round_key(state, keys[r]); emit(r, "AddRoundKey")
    return events

def decrypt_trace(block: bytes, key: bytes):
    if not isinstance(block, bytes) or len(block) != 16: raise ValueError("Block must be 16 bytes")
    keys=round_keys(key); nr=len(keys)-1
    state=c.bytes_to_state(block); events=[]
    def emit(r,step): events.append({"round":r,"step":step,"state":c.state_hex(state)})
    emit(nr,"input")
    state=c.add_round_key(state,keys[nr]); emit(nr,"AddRoundKey")
    for r in range(nr-1,-1,-1):
        state=c.inv_shift_rows(state);emit(r,"InvShiftRows")
        state=c.inv_sub_bytes(state);emit(r,"InvSubBytes")
        state=c.add_round_key(state,keys[r]);emit(r,"AddRoundKey")
        if r:
            state=c.inv_mix_columns(state);emit(r,"InvMixColumns")
    return events
