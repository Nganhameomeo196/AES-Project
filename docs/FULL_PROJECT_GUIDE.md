# AES Project – Hướng dẫn kỹ thuật và sử dụng

## 1. Giới thiệu dự án

AES Project là dự án nghiên cứu và triển khai thuật toán mã hóa đối xứng Advanced Encryption Standard (AES) bằng ngôn ngữ Python.

Dự án tập trung vào các nội dung:

- Nghiên cứu cơ sở lý thuyết của AES và thuật toán Rijndael.
- Triển khai AES-128, AES-192 và AES-256.
- Xây dựng các phép biến đổi và quá trình mở rộng khóa.
- Thực hiện mã hóa, giải mã và kiểm thử tính chính xác.
- Khảo sát các chế độ hoạt động ECB, CBC, CTR và GCM.
- Mô phỏng một số đặc điểm bảo mật và phương pháp phân tích mật mã.
- Đo hiệu năng, trực quan hóa kết quả và xây dựng giao diện minh họa.

**Phạm vi sử dụng:** Đây là chương trình triển khai AES bằng Python thuần phục vụ học tập, nghiên cứu và đánh giá kỹ thuật. Chương trình chưa được kiểm toán bảo mật độc lập và không được khuyến nghị sử dụng để bảo vệ dữ liệu nhạy cảm trong môi trường thực tế.

Đối với ứng dụng thực tế, cần sử dụng thư viện mật mã đã được kiểm định.

## 2. Cơ sở lý thuyết

### 2.1. Tổng quan về AES

AES là thuật toán mã hóa khối đối xứng được tiêu chuẩn hóa trong FIPS 197.

Các thông số cơ bản:

| Phiên bản | Độ dài khóa | Kích thước khối | Số vòng |
|---|---|---|---|
| AES-128 | 128 bit | 128 bit | 10 |
| AES-192 | 192 bit | 128 bit | 12 |
| AES-256 | 256 bit | 128 bit | 14 |

Dữ liệu của một khối AES được biểu diễn dưới dạng ma trận trạng thái (*State*) gồm 4 hàng và 4 cột byte.

### 2.2. Các phép biến đổi chính

Quá trình mã hóa AES sử dụng các phép biến đổi:

- **SubBytes:** Thay thế byte thông qua bảng S-box, tạo tính phi tuyến.
- **ShiftRows:** Dịch vòng các hàng của ma trận State.
- **MixColumns:** Biến đổi và khuếch tán dữ liệu trong từng cột.
- **AddRoundKey:** Kết hợp State với khóa vòng bằng phép XOR.

Quá trình giải mã sử dụng các phép biến đổi nghịch đảo tương ứng.

### 2.3. Mở rộng khóa

Thuật toán mở rộng khóa tạo ra các khóa vòng từ khóa ban đầu.

Các thành phần chính bao gồm:

- Word
- RotWord
- SubWord
- Rcon

Số lượng khóa vòng phụ thuộc vào phiên bản AES-128, AES-192 hoặc AES-256.

## 3. Cấu trúc mã nguồn

### 3.1. Các thành phần AES

| Tệp | Chức năng |
|---|---|
| `src/aes_modules.py` | Các phép biến đổi cơ bản của AES |
| `src/aes_core.py` | Các phép biến đổi dùng chung, phép nghịch đảo và xử lý State |
| `src/key_expansion.py` | Mở rộng khóa AES-128/192/256 |
| `src/aes_encrypt.py` | Thực hiện mã hóa khối AES |
| `src/aes_decrypt.py` | Thực hiện giải mã khối AES |
| `src/modes.py` | Các chế độ ECB, CBC, CTR và GCM |
| `src/main.py` | Chương trình chạy minh họa |
| `src/demo_ui.py` | Giao diện đồ họa bằng tkinter |

Các thành phần khác trong thư mục `src/` hỗ trợ giao diện dòng lệnh, truy vết và trực quan hóa quá trình hoạt động của AES.

### 3.2. Kiểm thử

Thư mục `tests/` chứa các bài kiểm thử dành cho:

- Các phép biến đổi AES.
- Mở rộng khóa và mã hóa, giải mã.
- Các bộ dữ liệu kiểm thử chuẩn.
- Các chế độ hoạt động ECB, CBC, CTR và GCM.
- Các trường hợp đầu vào không hợp lệ.
- Một số chức năng nâng cao và thí nghiệm.

Các bài kiểm thử giúp phát hiện lỗi triển khai và kiểm tra sự tương thích với các giá trị tham chiếu.

### 3.3. Thí nghiệm và kết quả

Thư mục `experiments/` chứa các chương trình phục vụ nghiên cứu và minh họa, bao gồm:

- Đo hiệu năng mã hóa và giải mã.
- Khảo sát hiệu ứng avalanche và tính khuếch tán.
- Minh họa đặc điểm của các chế độ mã hóa.
- Mô phỏng tìm kiếm khóa trên không gian khóa giới hạn.
- Một số mô phỏng liên quan đến phân tích mật mã, kênh kề và lỗi.
- Tạo biểu đồ và xuất dữ liệu thực nghiệm.

Thư mục `results/` lưu các kết quả dạng CSV và hình ảnh phục vụ phân tích, so sánh và trình bày.

**Lưu ý:** Các mô phỏng này có mục đích giáo dục. Chúng không chứng minh rằng AES đầy đủ đã bị phá vỡ hoặc có thể khôi phục khóa thực tế.

## 4. Các chế độ hoạt động

Dự án khảo sát bốn chế độ mã hóa:

| Chế độ | Đặc điểm |
|---|---|
| ECB | Mã hóa từng khối độc lập; có thể làm lộ mẫu dữ liệu |
| CBC | Liên kết các khối thông qua IV và sử dụng PKCS#7 padding |
| CTR | Tạo luồng khóa từ bộ đếm; sử dụng bộ đếm 128 bit theo thứ tự big-endian |
| GCM | Kết hợp mã hóa với xác thực dữ liệu thông qua GHASH và authentication tag |

### Lưu ý bảo mật

- Không tái sử dụng nonce của CTR hoặc GCM với cùng một khóa.
- Không sử dụng ECB để bảo vệ dữ liệu có cấu trúc hoặc mẫu lặp.
- CBC có padding nhưng không tự cung cấp tính xác thực.
- Không xem việc giải mã thành công là bằng chứng dữ liệu chưa bị chỉnh sửa nếu chế độ sử dụng không có xác thực.
- Các triển khai mật mã bằng Python thuần có thể chịu ảnh hưởng từ thời gian thực thi và đặc điểm truy cập bộ nhớ.

## 5. Môi trường thực hiện

Môi trường đề xuất:

- Python 3.11 trở lên.
- Visual Studio Code hoặc trình soạn thảo Python tương đương.
- Git để quản lý phiên bản.
- Các thư viện bổ sung được khai báo trong `requirements.txt`.

Các lệnh dưới đây được thực hiện tại thư mục gốc của dự án.

## 6. Hướng dẫn chạy chương trình

### 6.1. Cài đặt thư viện

```bash
python -m pip install -r requirements.txt
```

### 6.2. Chạy chương trình chính

```bash
python -m src.main
```

### 6.3. Chạy giao diện đồ họa

```bash
python -m src.demo_ui
```

Giao diện sử dụng tkinter để minh họa các chức năng mã hóa và giải mã được tích hợp trong chương trình.

### 6.4. Chạy toàn bộ kiểm thử

```bash
python -m unittest discover -s tests -v
```

Kết quả kiểm thử cần được kiểm tra sau mỗi lần thay đổi mã nguồn.

### 6.5. Chạy các thí nghiệm

Chạy chương trình minh họa các đặc điểm bảo mật:

```bash
python -m experiments.attack_demos
```

Đo hiệu năng:

```bash
python -m experiments.benchmark
```

Tạo biểu đồ từ dữ liệu:

```bash
python -m experiments.plot_results
```

Các thí nghiệm khác có thể được thực hiện thông qua những module tương ứng trong thư mục `experiments/`.

## 7. Kiểm tra tính chính xác theo chuẩn AES

Dự án sử dụng các bộ dữ liệu tham chiếu để đối chiếu kết quả mã hóa.

Plaintext chung:

```text
00112233445566778899aabbccddeeff
```

### AES-128

Key:

```text
000102030405060708090a0b0c0d0e0f
```

Ciphertext mong đợi:

```text
69c4e0d86a7b0430d8cdb78070b4c55a
```

### AES-192

Key:

```text
000102030405060708090a0b0c0d0e0f1011121314151617
```

Ciphertext mong đợi:

```text
dda97ca4864cdfe06eaf70a0ec0d7191
```

### AES-256

Key:

```text
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Ciphertext mong đợi:

```text
8ea2b7ca516745bfeafc49904b496089
```

Việc đối chiếu với các bộ dữ liệu chuẩn giúp kiểm tra tính chính xác của quá trình mã hóa. Ngoài ra, cần thực hiện kiểm thử giải mã và kiểm tra khả năng khôi phục plaintext ban đầu.

## 8. Phân tích bảo mật và mô phỏng

Dự án tìm hiểu các phương pháp phân tích mật mã, bao gồm:

- Brute-force attack.
- Differential cryptanalysis.
- Linear cryptanalysis.
- Related-key attack.
- Biclique attack.

Trong đó, các phương pháp phân tích nâng cao được nghiên cứu chủ yếu ở mức lý thuyết hoặc thông qua mô hình minh họa. Dự án không triển khai các cuộc tấn công khôi phục khóa thực tế đối với AES đầy đủ.

Các chủ đề kênh kề và lỗi được khảo sát gồm:

- Timing analysis.
- Cache analysis.
- Power analysis.
- Fault analysis.
- Các rủi ro xuất phát từ cách triển khai.

Kết quả benchmark Python không đủ để chứng minh sự rò rỉ khóa qua kênh kề. Các phép đo công suất, cache hoặc lỗi trên thiết bị thực tế cần có môi trường và thiết bị chuyên dụng.

## 9. Đánh giá hiệu năng và tái lập kết quả

Các thí nghiệm hiệu năng có thể xem xét:

- Thời gian mở rộng khóa.
- Thời gian mã hóa.
- Thời gian giải mã.
- Sự khác biệt giữa AES-128, AES-192 và AES-256.
- Sự khác biệt giữa các chế độ hoạt động.

Để kết quả có thể kiểm tra và tái lập, cần ghi nhận:

- Cấu hình CPU và hệ điều hành.
- Phiên bản Python.
- Số lần thực hiện phép đo.
- Phương pháp tổng hợp số liệu, chẳng hạn trung bình hoặc trung vị.
- Các yếu tố gây sai lệch do môi trường thực thi Python.

Không sử dụng số liệu hoặc hình ảnh thực nghiệm chưa được chạy và kiểm chứng trên môi trường tương ứng.

Các tệp CSV và biểu đồ trong `results/` cần được đối chiếu với chương trình tạo ra chúng.

## 10. Hướng phát triển và giới hạn

### 10.1. Hướng phát triển

Dự án có thể tiếp tục được mở rộng theo các hướng:

- Bổ sung kiểm thử và các trường hợp biên.
- Cải thiện giao diện và trải nghiệm sử dụng.
- Mở rộng bộ thí nghiệm và trực quan hóa.
- So sánh hiệu năng trên các môi trường khác nhau.
- Nghiên cứu sâu hơn về an toàn triển khai mật mã.

### 10.2. Giới hạn

- Chương trình phục vụ mục đích học tập và nghiên cứu.
- Mã nguồn chưa trải qua kiểm toán bảo mật độc lập.
- Các phép đo bằng Python chịu ảnh hưởng của trình thông dịch và môi trường hệ thống.
- Một số nội dung phân tích mật mã và kênh kề chỉ mang tính mô phỏng.
- Việc vượt qua các bộ kiểm thử chuẩn không đồng nghĩa với bảo đảm an toàn mật mã trong môi trường thực tế.

## 11. Kết luận

Dự án AES Project cung cấp một môi trường nghiên cứu và thực hành về thuật toán AES, từ các phép biến đổi cơ bản đến mã hóa, giải mã, các chế độ hoạt động và đánh giá thực nghiệm.

Việc kết hợp triển khai thuật toán, kiểm thử theo dữ liệu chuẩn, mô phỏng bảo mật và trực quan hóa kết quả giúp hỗ trợ quá trình tìm hiểu AES ở cả khía cạnh lý thuyết lẫn thực hành.

Dự án được xây dựng phục vụ mục tiêu học tập và có thể tiếp tục phát triển, hoàn thiện trong các giai đoạn tiếp theo.