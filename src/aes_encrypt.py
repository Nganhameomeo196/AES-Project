# src/aes_encrypt.py
# Khung chương trình AES Encryption
# Sẽ được hoàn thiện ở Tuần 3.


from src.aes_modules import (
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key
)


def aes_encrypt(state, round_keys):
    """
    Khung hàm mã hóa AES.

    Tuần 2:
        Chuẩn bị cấu trúc và các module thành phần.

    Tuần 3:
        Hoàn thiện quá trình:
        - Initial Round
        - Main Rounds
        - Final Round
    """

    # Initial Round
    # state = add_round_key(state, round_keys[0])

    # Main Rounds
    # for round_key in round_keys[1:-1]:
    #     state = sub_bytes(state)
    #     state = shift_rows(state)
    #     state = mix_columns(state)
    #     state = add_round_key(state, round_key)

    # Final Round
    # state = sub_bytes(state)
    # state = shift_rows(state)
    # state = add_round_key(state, round_keys[-1])

    return state