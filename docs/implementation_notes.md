# AES Project – Ghi chú triển khai, tích hợp và kiểm thử

## 1. Tổng quan

Tài liệu mô tả cấu trúc triển khai, quá trình tích hợp các thành phần và phương pháp kiểm thử thuật toán Advanced Encryption Standard (AES) trong dự án.

Mục tiêu là bảo đảm các module hoạt động thống nhất, xử lý đúng dữ liệu đầu vào và cho kết quả mã hóa, giải mã phù hợp với tiêu chuẩn AES.

Dự án được xây dựng bằng Python, hỗ trợ AES-128, AES-192 và AES-256, đồng thời tích hợp các chế độ hoạt động ECB, CBC, CTR và GCM phục vụ học tập và nghiên cứu.

## 2. Các thành phần triển khai

### 2.1. Các phép biến đổi AES

**`src/aes_modules.py`**

Chứa các phép biến đổi cơ bản của thuật toán AES:

- `SubBytes`: Thay thế các byte thông qua bảng S-box.
- `ShiftRows`: Dịch vòng các hàng của ma trận trạng thái.
- `MixColumns`: Trộn dữ liệu trong từng cột.
- `AddRoundKey`: Kết hợp dữ liệu với khóa vòng bằng phép XOR.

**`src/aes_core.py`**

Cung cấp các chức năng xử lý chung của AES, bao gồm:

- Biểu diễn và xử lý ma trận State.
- Các phép biến đổi thuận và nghịch đảo.
- Bảng inverse S-box và phép inverse MixColumns.
- Chuyển đổi dữ liệu theo thứ tự cột (column-major).

### 2.2. Mở rộng khóa

**`src/key_expansion.py`**

Thực hiện quá trình mở rộng khóa để tạo các khóa vòng cho:

| Phiên bản | Độ dài khóa | Số vòng |
|---|---|---|
| AES-128 | 128 bit | 10 |
| AES-192 | 192 bit | 12 |
| AES-256 | 256 bit | 14 |

Quá trình mở rộng khóa sử dụng các phép biến đổi như RotWord, SubWord và các hằng số Rcon.

### 2.3. Mã hóa và giải mã

**`src/aes_encrypt.py`**

Thực hiện mã hóa một khối dữ liệu 16 byte theo cấu trúc AES, sử dụng các khóa vòng được tạo từ quá trình mở rộng khóa.

**`src/aes_decrypt.py`**

Thực hiện giải mã khối dữ liệu bằng các phép biến đổi nghịch đảo tương ứng.

Việc mã hóa và giải mã cần bảo đảm:

- Đúng kích thước khối 128 bit.
- Hỗ trợ các độ dài khóa hợp lệ.
- Áp dụng đúng số vòng AES.
- Sử dụng đúng thứ tự các phép biến đổi.
- Khôi phục chính xác plaintext khi giải mã với khóa phù hợp.

### 2.4. Các chế độ hoạt động

**`src/modes.py`**

Triển khai các chế độ mã hóa:

- **ECB:** Mã hóa các khối độc lập.
- **CBC:** Liên kết các khối và sử dụng PKCS#7 padding.
- **CTR:** Sử dụng bộ đếm để tạo luồng khóa.
- **GCM:** Kết hợp mã hóa với xác thực dữ liệu.

Các chế độ này mở rộng khả năng xử lý dữ liệu so với hàm AES mã hóa một khối đơn lẻ.

## 3. Tích hợp các module

Các thành phần được tổ chức trong thư mục `src/` để hỗ trợ việc gọi và sử dụng thống nhất trong chương trình.

Các nội dung tích hợp chính bao gồm:

- Chuẩn hóa cách import giữa các module.
- Kết nối quá trình mở rộng khóa với mã hóa và giải mã.
- Kiểm tra độ dài khóa, plaintext và ciphertext.
- Hỗ trợ cả ba phiên bản AES-128, AES-192 và AES-256.
- Tổ chức chương trình để có thể chạy từ thư mục gốc dự án.
- Đảm bảo các phép biến đổi dùng chung có kết quả nhất quán.

Chương trình chính được chạy bằng lệnh:

```bash
python -m src.main
```

Ngoài ra, dự án có giao diện minh họa bằng tkinter:

```bash
python -m src.demo_ui
```

## 4. Kiểm thử tính chính xác

### 4.1. Kiểm thử theo dữ liệu chuẩn

Dự án sử dụng các bộ dữ liệu kiểm thử tham chiếu FIPS-197 cho AES-128, AES-192 và AES-256.

Việc đối chiếu ciphertext với giá trị chuẩn giúp phát hiện các lỗi triển khai mà kiểm thử mã hóa rồi giải mã đơn thuần có thể không phát hiện được.

### 4.2. Kiểm thử mã hóa và giải mã

Kiểm thử round-trip được thực hiện theo quy trình:

```text
Plaintext
    |
    v
AES Encryption
    |
    v
Ciphertext
    |
    v
AES Decryption
    |
    v
Plaintext ban đầu
```

Kết quả giải mã phải trùng khớp với plaintext ban đầu khi sử dụng đúng khóa và các tham số cần thiết.

### 4.3. Kiểm thử mở rộng khóa

Kiểm tra số lượng khóa vòng và kết quả mở rộng khóa đối với từng phiên bản AES.

### 4.4. Kiểm thử tính nhất quán giữa các module

Đối chiếu kết quả của các phép biến đổi trong `aes_modules.py` và `aes_core.py` nhằm phát hiện sự khác biệt không mong muốn.

Hai module có một số chức năng tương đồng, vì vậy cần chú ý bảo đảm tính nhất quán khi chỉnh sửa hoặc mở rộng mã nguồn.

### 4.5. Kiểm thử dữ liệu đầu vào

Các trường hợp kiểm thử bao gồm:

- Khóa có độ dài không hợp lệ.
- Khối plaintext không đúng 16 byte đối với hàm mã hóa khối.
- Khối ciphertext không đúng kích thước.
- Dữ liệu đầu vào không đáp ứng yêu cầu của hàm xử lý.

### 4.6. Kiểm thử các chế độ hoạt động

Các chế độ ECB, CBC, CTR và GCM được kiểm tra thông qua các bài kiểm thử tương ứng trong thư mục `tests/`.

Đối với GCM, cần kiểm tra cả kết quả mã hóa và khả năng phát hiện dữ liệu hoặc thẻ xác thực không hợp lệ.

## 5. Hướng dẫn chạy kiểm thử

Từ thư mục gốc của dự án, chạy:

```bash
python -m unittest discover -s tests -v
```

Các tệp kiểm thử được tổ chức trong thư mục `tests/`, bao gồm kiểm thử thành phần, kiểm thử tích hợp và kiểm thử các chế độ hoạt động.

Trong đó, `tests/test_integration.py` tập trung vào các nội dung:

- Đối chiếu kết quả với dữ liệu chuẩn.
- Kiểm tra quá trình mã hóa và giải mã.
- Kiểm tra tính nhất quán giữa các module.
- Kiểm tra dữ liệu đầu vào không hợp lệ.

Sau mỗi thay đổi quan trọng đối với mã nguồn, cần chạy lại bộ kiểm thử để phát hiện các lỗi phát sinh.

## 6. Lưu ý kỹ thuật và bảo mật

- AES sử dụng kích thước khối cố định 128 bit, tương đương 16 byte.
- AES-128, AES-192 và AES-256 khác nhau về độ dài khóa và số vòng xử lý.
- Các hàm mã hóa khối cần được phân biệt với các chế độ xử lý dữ liệu nhiều khối.
- Kiểm thử round-trip không thay thế được kiểm thử theo dữ liệu chuẩn.
- ECB có thể làm lộ mẫu dữ liệu lặp.
- CBC không tự cung cấp tính xác thực cho dữ liệu.
- Không được tái sử dụng nonce của CTR hoặc GCM với cùng một khóa.
- Các mô phỏng và phép đo trong Python không đủ để chứng minh tính an toàn trước các cuộc tấn công kênh kề.

Dự án phục vụ mục đích học tập và nghiên cứu, không thay thế các thư viện mật mã đã được kiểm toán bảo mật trong ứng dụng thực tế.

## 7. Kết luận

Việc tổ chức các thành phần AES thành những module riêng biệt giúp chương trình dễ kiểm thử, bảo trì và mở rộng.

Quá trình tích hợp kết hợp với kiểm thử theo dữ liệu chuẩn, kiểm thử round-trip và kiểm tra đầu vào giúp đánh giá tính chính xác của hệ thống.

Tài liệu này cung cấp thông tin kỹ thuật về cách triển khai và kiểm thử AES, hỗ trợ việc tìm hiểu mã nguồn và phát triển dự án trong các giai đoạn tiếp theo.