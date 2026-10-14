# AES Project – Tuần 3 (Integration + Test của Hà)

Bản này phát triển từ ZIP repository do Hà cung cấp; giữ nguyên các thuật toán của nhóm, chỉ chuẩn hóa import, thêm validation, demo và test tích hợp.

Chạy từ thư mục gốc:

```powershell
python -m src.main
python -m unittest discover -s tests -v
python -m tests.test_aes_modules
```

`test_aes_modules.py` là bài test kiểu in PASS/FAIL cũ, nên chạy riêng; `unittest discover` chạy bài test tự động mới.

Các file thay đổi: `src/aes_core.py`, `src/aes_encrypt.py`, `src/aes_decrypt.py`, `src/key_expansion.py`, `src/main.py`, `.gitignore`.
Các file mới: `tests/test_integration.py`, `docs/implementation_notes.md`, `README_WEEK3.md`.

**Không có benchmark đo thời gian trong tuần 3**; code hiện tại là nền tảng để viết benchmark tuần 4.
