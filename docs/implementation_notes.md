# Tuần 3 – Hà: Integration + Test

## Đã có từ repository gốc
- `aes_modules.py`: SubBytes, ShiftRows, MixColumns, AddRoundKey (tuần 2).
- `key_expansion.py`: sinh round key cho AES-128/192/256.
- `aes_core.py`: State và các phép biến đổi thuận/nghịch.
- `aes_encrypt.py`, `aes_decrypt.py`: xử lý khối 16 byte.

## Công việc tích hợp
- Chuẩn hóa import để chạy được `python -m src.main` từ gốc dự án.
- Bổ sung kiểm tra độ dài plaintext/ciphertext và key.
- Tạo demo cả ba độ dài khóa trong `src/main.py`.
- Tạo `tests/test_integration.py`: test vector FIPS-197, round-trip, số round key, so sánh module tuần 2 và module core, input không hợp lệ.
- Sửa `.gitignore` UTF-16 cũ thành UTF-8 chuẩn.

## Lưu ý
- Code minh họa AES một khối 16 byte, **chưa** có mode ECB/CBC/CTR/GCM, padding, nonce/IV hay xác thực. Không dùng để bảo vệ dữ liệu thực tế.
- `aes_modules.py` và `aes_core.py` trùng một số phép biến đổi: tuần 4 nên thống nhất một nguồn duy nhất hoặc biến `aes_core.py` thành lớp adapter.
- Test vector chuẩn giúp phát hiện lỗi mà chỉ round-trip có thể bỏ sót.
