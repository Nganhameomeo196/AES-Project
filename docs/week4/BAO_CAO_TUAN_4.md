# BÁO CÁO NGHIÊN CỨU VÀ ĐÁNH GIÁ AN TOÀN MẬT MÃ THUẬT TOÁN AES
## Chuyên đề: Phân tích bảo mật, Khảo sát chế độ hoạt động và Thực nghiệm tấn công (Tuần 4)

---

## MỤC LỤC
1. [Tổng hợp các hướng tấn công đã nghiên cứu ở Tuần 3 và phân biệt lý thuyết vs mô phỏng](#1-tổng-hợp-các-hướng-tấn-công-đã-nghiên-cứu-ở-tuần-3)
2. [Thực nghiệm ECB Pattern Leakage (Hiện tượng lộ mẫu dữ liệu)](#2-thực-nghiệm-ecb-pattern-leakage)
3. [Giải thích nguyên lý toán học vì sao ECB làm lộ mẫu dữ liệu](#3-giải-thích-nguyên-lý-toán-học-của-ecb)
4. [Thực nghiệm Tampering (Chỉnh sửa Ciphertext)](#4-thực-nghiệm-tampering)
5. [So sánh phản ứng khi dữ liệu bị chỉnh sửa giữa các chế độ (ECB, CBC, CTR, GCM)](#5-so-sánh-phản-ứng-chỉnh-sửa-giữa-các-mode)
6. [Thực nghiệm Brute-Force Simulation với không gian khóa thu nhỏ](#6-thực-nghiệm-brute-force-với-không-gian-khóa-thu-nhỏ)
7. [Giải thích vì sao Brute-Force trên AES-128/192/256 bất khả thi trong thực tế](#7-giải-thích-tính-bất-khả-thi-của-brute-force-aes-chuẩn)
8. [Thực nghiệm và phân tích hiệu ứng tuyết lở (Avalanche Effect)](#8-thực-nghiệm-và-phân-tích-avalanche-effect)
9. [Tổng hợp và đánh giá các mô phỏng Timing, Cache, Power và Fault Attack](#9-tổng-hợp-và-đánh-giá-các-mô-phỏng-side-channel--fault)
10. [Phân biệt mô phỏng Side-Channel phần mềm với tấn công thực tế trên phần cứng](#10-phân-biệt-mô-phỏng-side-channel-và-tấn-công-phần-cứng-thực-tế)
11. [Liên hệ các hướng Differential, Linear, Related-Key, Biclique và giới hạn trên AES đầy đủ](#11-liên-hệ-các-hướng-tấn-công-tuần-3-và-giới-hạn-áp-dụng)
12. [Bảng so sánh tổng hợp các hướng tấn công trên AES](#12-bảng-so-sánh-tổng-hợp-các-hướng-tấn-công)
13. [Đề xuất các biện pháp bảo mật khi triển khai AES trong thực tế](#13-đề-xuất-biện-pháp-bảo-mật-khi-triển-khai-aes)
14. [Phân tích giới hạn của chương trình nghiên cứu so với hệ thống thực tế](#14-phân-tích-giới-hạn-của-chương-trình-nghiên-cứu)

---

## 1. Tổng hợp các hướng tấn công đã nghiên cứu ở Tuần 3
Trong Tuần 3, nhóm đã tiến hành khảo sát cơ sở lý thuyết và mô hình toán học của các kỹ thuật phân tích mật mã kinh điển và hiện đại áp dụng lên khối mã AES:
- **Tấn công vét cạn (Brute-Force Attack):** Thử toàn bộ không gian khóa khả dĩ.
- **Phân tích sai phân (Differential Cryptanalysis):** Khai thác xác suất truyền sai phân $\Delta P \to \Delta C$ qua các phép biến đổi phi tuyến (S-box) và khuếch tán (ShiftRows, MixColumns).
- **Phân tích tuyến tính (Linear Cryptanalysis):** Xây dựng các biểu thức xấp xỉ tuyến tính giữa bit plaintext, ciphertext và khóa.
- **Tấn công khóa liên quan (Related-Key Attack):** Khai thác tính đối xứng hoặc khiếm khuyết trong giải thuật sinh khóa vòng (Key Schedule) khi biết hoặc chọn được độ lệch giữa hai khóa $\Delta K$.
- **Tấn công Biclique (Biclique Cryptanalysis):** Kỹ thuật mở rộng từ Meet-in-the-Middle nhằm giảm độ phức tạp tính toán trên toàn bộ số vòng của AES.
- **Tấn công kênh kề & lỗi (Side-Channel & Fault Attacks):** Khai thác dấu vết vật lý như thời gian thực thi (Timing), hành vi truy cập bộ đệm (Cache), công suất tiêu thụ (Power Analysis - CPA), hoặc cố tình gây lỗi tính toán (Differential Fault Analysis - DFA).

### Phân biệt rạch ròi giữa Tấn công lý thuyết và Mô phỏng thực tế:
- **Tấn công lý thuyết (Theoretical / Cryptanalytic Attack):** 
  - Đánh giá trên mô hình toán học thuần túy, chứng minh thuật toán yếu hơn so với mức bảo mật danh định (security margin). 
  - Thường chỉ áp dụng trên số vòng rút gọn (reduced rounds) hoặc nếu áp dụng trên toàn bộ vòng (như Biclique) thì chỉ giảm nhẹ độ phức tạp tính toán (ví dụ: $2^{128} \to 2^{126.1}$), vẫn vượt xa năng lực tính toán của nhân loại. Kẻ tấn công đòi hỏi những điều kiện phi thực tế (như hàng tỷ terabyte cặp plaintext-ciphertext đã biết hoặc chọn trước).
- **Mô phỏng thực tế (Empirical / Educational Simulation):**
  - Xây dựng trên môi trường phần mềm với các điều kiện thu nhỏ hoặc kiểm soát được (như không gian khóa 8-bit, mô hình rò rỉ trọng số Hamming nhân tạo, tiêm lỗi phần mềm tại một byte cụ thể).
  - Mục đích là trực quan hóa cơ chế lan truyền lỗi, kiểm chứng nguyên lý hoạt động của tấn công và nâng cao nhận thức bảo mật, **không đại diện cho một lỗ hổng thực tế có thể khai thác trực tiếp trên hệ thống AES-128/192/256 thương mại**.

---

## 2. Thực nghiệm ECB Pattern Leakage
*Kịch bản thực thi:* File kịch bản `experiments/week4_security.py` và `experiments/ecb_image.py`.
- **Dữ liệu kiểm thử:** Một bản tin gồm 4 khối (64 bytes), trong đó Khối 1 = Khối 2 = Khối 4 = `b"A" * 16`, Khối 3 = `b"B" * 16`.
- **Thực thi trên các chế độ:** ECB, CBC, CTR, GCM với cùng một khóa bí mật 128-bit.

### Kết quả đo đạc thực tế:
```text
Plaintext (64 bytes = 4 blocks): Block 1 = Block 2 = Block 4 = 'A'*16, Block 3 = 'B'*16

[AES-ECB Ciphertext Blocks]:
  Block 1: dd4b1a0b47daa7067d0b59d95d58a6ae
  Block 2: dd4b1a0b47daa7067d0b59d95d58a6ae
  Block 3: 87f815ad0e513346e0afe99814b1a504
  Block 4: dd4b1a0b47daa7067d0b59d95d58a6ae
=> Kiểm tra Block 1 == Block 2 == Block 4: True (LỘ MẪU DỮ LIỆU 100%!)

[AES-CBC Ciphertext Blocks]:
  Block 1: 265c6c2548555838c5fab3b6887803c8
  Block 2: d2d01700caf15385b3d5e19791c71297
  Block 3: 81cdd44f33acce7126a6af7dc710c7b0
  Block 4: e0be074820d18a3a35a11ce6b0e60df8
```
- **Hiện tượng quan sát:** 
  - Trong chế độ ECB, ba khối bản rõ giống nhau tạo ra ba khối bản mã trùng khít từng byte.
  - Ngược lại, ở CBC, CTR và GCM, nhờ có Vector khởi tạo (IV), Bộ đếm (Counter), và Nonce, các khối bản mã hoàn toàn ngẫu nhiên và phân biệt nhau 100%.
  - Thí nghiệm mã hóa hình ảnh bitmap/PPM cho thấy ảnh mã hóa bằng ECB vẫn giữ nguyên đường viền và cấu trúc đồ họa của hình gốc (hiện tượng ECB Penguin nổi tiếng).

---

## 3. Giải thích nguyên lý toán học của ECB
Chế độ ECB (Electronic Codebook) hoạt động theo nguyên lý ánh xạ độc lập từng khối:
$$C_i = E_K(P_i)$$
Trong đó:
- $P_i$ là khối bản rõ thứ $i$.
- $C_i$ là khối bản mã thứ $i$.
- $E_K$ là hàm biến đổi mã hóa khối AES với khóa $K$.

### Nguyên nhân gây lộ mẫu:
1. **Tính chất tất định (Determinism):** Hàm mã hóa AES $E_K$ là một hoán vị tất định trên không gian $\{0, 1\}^{128}$. Với cùng một khóa cố định $K$, ánh xạ $P \to C$ là duy nhất (1-to-1). Do đó, nếu $P_i = P_j$ thì bắt buộc $E_K(P_i) = E_K(P_j) \implies C_i = C_j$.
2. **Thiếu tính ngẫu nhiên hóa (Lack of Randomization):** ECB không sử dụng Vector khởi tạo (IV) hoặc Nonce. 
3. **Không có liên kết trạng thái (No Chaining):** Việc mã hóa khối $i$ không phụ thuộc vào trạng thái của khối $i-1$ (như trong CBC) hay giá trị bộ đếm thay đổi (như trong CTR).
4. **Hệ quả an ninh:** Kẻ tấn công thụ động (eavesdropper) dù không thể giải mã khóa nhưng có thể dễ dàng phân tích tần suất, phát hiện các mẫu lặp lại trong tài liệu, nhận diện định dạng file header, cấu trúc gói tin mạng, hoặc chèn/hoán đổi các khối mã hóa mà không làm hỏng tính toàn vẹn cục bộ của các khối còn lại (Block Replay Attack).

---

## 4. Thực nghiệm Tampering (Chỉnh sửa Ciphertext)
*Kịch bản thực thi:* Hàm `demo_tampering()` trong `experiments/week4_security.py`.
- **Dữ liệu:** Bản rõ 48 bytes gồm 3 khối:
  - Khối 1: `b"Block01_16Bytes!"`
  - Khối 2: `b"Block02_16Bytes!"`
  - Khối 3: `b"Block03_16Bytes!"`
- **Tác vụ can thiệp:** Lật đúng 1 bit tại vị trí byte 16 (byte đầu tiên của Khối 2 trong bản mã) và tiến hành giải mã để kiểm tra hành vi khôi phục dữ liệu trên cả 4 chế độ: ECB, CBC, CTR, GCM.

---

## 5. So sánh phản ứng chỉnh sửa giữa các mode
Kết quả ghi nhận từ thực nghiệm:

| Chế độ | Phản ứng khi lật 1 bit Ciphertext tại Khối 2 | Khối 1 | Khối 2 (Bị sửa) | Khối 3 | Cảnh báo toàn vẹn |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **ECB** | Lỗi khuếch tán cô lập trong khối | Nguyên vẹn | **Hỏng hoàn toàn (Rác 16 byte)** | Nguyên vẹn | Không cảnh báo |
| **CBC** | Lan truyền lỗi sang khối kế tiếp | Nguyên vẹn | **Hỏng hoàn toàn (Rác 16 byte)** | **Bị lật đúng 1 bit tương ứng** | Không cảnh báo |
| **CTR** | Lật bit cục bộ 1-1 (Mã dòng) | Nguyên vẹn | **Bị lật đúng 1 bit tương ứng** | Nguyên vẹn | Không cảnh báo |
| **GCM** | Xác thực thất bại & Từ chối | **HỦY** | **HỦY** | **HỦY** | **Phát hiện ngay (ValueError)** |

### Phân tích chi tiết:
1. **ECB:** Do mỗi khối giải mã độc lập $P_i = D_K(C_i)$, sai lệch 1 bit tại $C_2$ làm hàm giải mã AES khôi phục sai hoàn toàn trạng thái nội tại của khối 2 do hiệu ứng tuyết lở nghịch đảo, biến toàn bộ $P_2$ thành rác ngẫu nhiên. Khối 1 và Khối 3 không bị ảnh hưởng.
2. **CBC:** Giải mã theo công thức: $P_i = D_K(C_i) \oplus C_{i-1}$. 
   - Khi $C_2$ bị sửa, phép giải mã $D_K(C_2)$ làm hỏng toàn bộ $P_2$.
   - Tại khối tiếp theo: $P_3 = D_K(C_3) \oplus C_2$. Vì $D_K(C_3)$ vẫn đúng, bit bị đảo trong $C_2$ truyền thẳng qua phép XOR sang $P_3$. Đây chính là lỗ hổng **Bit-Flipping Attack** cho phép kẻ tấn công sửa đổi có chủ đích nội dung bản rõ giải mã mà không cần biết khóa.
3. **CTR:** Hoạt động như mã dòng: $P_i = C_i \oplus E_K(Counter_i)$. Việc sửa bit tại vị trí nào trên bản mã sẽ lật đúng bit tại vị trí tương ứng trên bản rõ. Kẻ tấn công có thể thay đổi dữ liệu (ví dụ đổi số tiền chuyển khoản từ 1000 thành 9000) mà hệ thống không có cách nào phát hiện nếu không có lớp xác thực đi kèm.
4. **GCM (Galois/Counter Mode):** Là chế độ xác thực liên kết AEAD (Authenticated Encryption with Associated Data). Mọi can thiệp vào Ciphertext, Tag, hoặc Associated Data (AAD) đều làm sai lệch thẻ xác thực GHASH. Hàm giải mã `gcm_decrypt` kích hoạt ngoại lệ `ValueError: GCM authentication tag mismatch` và lập tức hủy bỏ toàn bộ quá trình, không trả về bất kỳ dữ liệu rác nào.

---

## 6. Thực nghiệm Brute-Force với không gian khóa thu nhỏ
*Kịch bản thực thi:* Hàm `demo_bruteforce()` trong `experiments/week4_security.py`.
- **Mô hình giả lập:** Giả định kẻ tấn công đã biết 15 byte đầu của khóa 128-bit thông qua kênh kề, chỉ còn lại byte cuối cùng (8-bit) chưa biết $\implies$ Không gian khóa $2^8 = 256$ trường hợp.
- **Giá trị khóa bí mật cần tìm:** Byte 73 (`0x49`).
- **Bản rõ mục tiêu:** `00112233445566778899aabbccddeeff`.

### Kết quả đo đạc:
- **Thời gian tìm ra khóa:** $15.953 \text{ ms}$.
- **Số phép thử:** 74 lần thử (tính cả khóa chính xác).
- **Tốc độ vét cạn đo được trên Python thuần:** $\approx 4,639 \text{ keys/giây}$.

---

## 7. Giải thích tính bất khả thi của Brute-Force AES chuẩn
Từ tốc độ đo đạc thực nghiệm, nhóm tính toán thời gian cần thiết để vét cạn không gian khóa đầy đủ:

$$\text{Không gian khóa AES-128} = 2^{128} \approx 3.4028 \times 10^{38} \text{ khóa}$$

### Đánh giá thời gian:
1. **Với máy tính thông thường (đo đạc thực tế):**
   $$T = \frac{2^{128}}{4,639 \text{ keys/giây}} \approx 7.33 \times 10^{34} \text{ giây} \approx 2.32 \times 10^{27} \text{ năm}$$
2. **Với siêu máy tính nhanh nhất hành tinh (Ví dụ Frontier, xử lý được $10^{18}$ phép tính/giây):**
   $$T_{super} = \frac{2^{128}}{10^{18} \text{ keys/giây}} \approx 3.40 \times 10^{20} \text{ giây} \approx 1.07 \times 10^{13} \text{ năm}$$
   *So sánh:* Tuổi của toàn bộ vũ trụ từ vụ nổ Big Bang đến nay chỉ khoảng $1.38 \times 10^{10}$ năm. Thời gian vét cạn AES-128 bằng siêu máy tính vẫn gấp **gần 1.000 lần tuổi của vũ trụ!**
3. **Với AES-192 ($2^{192}$) và AES-256 ($2^{256}$):** Thời gian tính bằng hàng tỷ tỷ lần tuổi vũ trụ, hoàn toàn nằm ngoài giới hạn vật lý.

### Giới hạn nhiệt động lực học (Nguyên lý Landauer):
Theo định luật vật lý nhiệt động học, năng lượng tối thiểu để thay đổi trạng thái của 1 bit thông tin ở nhiệt độ phòng ($300\text{K}$) là:
$$E_{min} = k_B \cdot T \cdot \ln(2) \approx 2.87 \times 10^{-21} \text{ Joules}$$
Để chỉ đơn giản là *đếm* qua $2^{128}$ trạng thái, một hệ thống máy tính lý tưởng cần tiêu tốn:
$$E_{total} \approx 3.4 \times 10^{38} \times 2.87 \times 10^{-21} \approx 9.76 \times 10^{17} \text{ Joules}$$
Năng lượng này tương đương hàng chục quả bom khinh khí nhiệt hạch nổ cùng lúc. Với AES-256 ($2^{256}$), năng lượng cần thiết vượt xa tổng năng lượng bức xạ của toàn bộ Mặt Trời từ khi hình thành đến khi lụi tàn. **Do đó, brute-force AES đầy đủ là bất khả thi về mặt vật lý.**

---

## 8. Thực nghiệm và phân tích Avalanche Effect
*Kịch bản thực thi:* Hàm `demo_avalanche()` trong `experiments/week4_security.py` và `experiments/avalanche.py`.
- **Mục tiêu:** Đo lường tiêu chuẩn tuyết lở ngặt nghèo (Strict Avalanche Criterion - SAC): Khi lật 1 bit đầu vào (bản rõ hoặc khóa), mỗi bit đầu ra phải thay đổi với xác suất xấp xỉ 50% ($64 / 128$ bit).
- **Phương pháp đo:** Lật tuần tự từng bit từ bit 1 đến bit 128 trên bản rõ (giữ nguyên khóa) và trên khóa (giữ nguyên bản rõ), tính khoảng cách Hamming (số bit khác biệt) trên bản mã.

### Kết quả đo đạc:
- **Thay đổi 1 bit Plaintext (128 vị trí):**
  - Số bit đổi thấp nhất (Min): **47 bit**
  - Số bit đổi cao nhất (Max): **79 bit**
  - Trung bình: **63.27 / 128 bit (49.43%)**
- **Thay đổi 1 bit Cipher Key (128 vị trí):**
  - Số bit đổi thấp nhất (Min): **48 bit**
  - Số bit đổi cao nhất (Max): **79 bit**
  - Trung bình: **63.85 / 128 bit (49.88%)**

### Đánh giá:
Kết quả trung bình thực nghiệm đạt **49.43%** và **49.88%**, bám sát ngưỡng lý tưởng $50.00\%$. Điều này chứng minh sự kết hợp hoàn hảo giữa tính phi tuyến cao của bảng `SubBytes` (S-box) và tính khuếch tán tối ưu của `ShiftRows` cùng `MixColumns` giúp phân tán triệt để thông tin, triệt tiêu mọi tương quan cục bộ chỉ sau vài vòng lặp.

---

## 9. Tổng hợp và đánh giá các mô phỏng Side-Channel & Fault
Dự án đã xây dựng 4 kịch bản mô phỏng các kỹ thuật tấn công vật lý:

### 9.1. Tấn công định thời (Timing Attack - `timing_demo.py`)
- **Nguyên lý:** So sánh chuỗi xác thực từng byte rời rạc (`vulnerable_compare`). Quá trình so sánh dừng lại ngay khi phát hiện byte đầu tiên sai (`early return`), dẫn đến sự chênh lệch thời gian thực thi đo bằng nanosecond giữa byte đúng và byte sai.
- **Giải pháp kiểm chứng:** Sử dụng hàm so sánh thời gian cố định `hmac.compare_digest` để loại bỏ hoàn toàn sự rò rỉ thời gian.

### 9.2. Tấn công phân tích Cache (`cache_analysis.py`)
- **Nguyên lý:** Bảng S-box của AES gồm 256 phần tử, được chia vào các dòng bộ đệm (cache line/bucket, 16-64 bytes). Dựa vào hiện tượng cache hit/miss hoặc thời gian truy cập (kỹ thuật Flush+Reload), kẻ tấn công suy đoán được chỉ số bucket mà bảng S-box được truy xuất: `SBOX[Plaintext ^ Key] // 16`.
- **Kết quả mô phỏng:** Chỉ sau 16-32 mẫu quan sát, số lượng ứng viên của byte khóa bị thu hẹp từ 256 xuống còn duy nhất 1 giá trị chính xác.

### 9.3. Tấn công công suất tương quan (Correlation Power Analysis - CPA - `sidechannel_sim.py`)
- **Nguyên lý:** Công suất tiêu thụ tức thời của vi mạch CMOS tỉ lệ thuận với số lượng transistor chuyển trạng thái (mô hình trọng số Hamming). Kẻ tấn công tính hệ số tương quan Pearson giữa công suất giả định cho từng ứng viên khóa $k \in [0, 255]$ và dạng sóng công suất đo được.
- **Kết quả mô phỏng:** Với 256 mẫu kèm nhiễu Gaussian ($\sigma = 0.7$), hệ số tương quan của byte khóa đúng vượt trội hoàn toàn ($\approx 0.85$) so với các khóa sai (dao động quanh $0.0$). Byte khóa bí mật `0xA7` được khôi phục chính xác 100%.

### 9.4. Tấn công lỗi vi sai (Differential Fault Analysis - DFA - `fault_demo.py`)
- **Nguyên lý:** Mô phỏng mô hình toán học Piret-Quisquater: Tiêm 1 lỗi bit vào 1 byte trạng thái State tại vòng 9 (trước phép biến đổi `MixColumns` cuối cùng).
- **Kết quả:** Phép nhân ma trận cột `MixColumns` ở vòng 9 khuếch tán lỗi từ 1 byte thành đúng 4 byte lỗi trong cùng một cột ở vòng 10. Bằng cách so sánh bản mã chuẩn và bản mã bị lỗi, kẻ tấn công có thể giải hệ phương trình vi sai và khôi phục toàn bộ khóa vòng 10 chỉ sau 2-4 lần tiêm lỗi thành công.

---

## 10. Phân biệt mô phỏng Side-Channel và tấn công phần cứng thực tế

| Tiêu chí | Mô phỏng trên phần mềm (Dự án) | Tấn công thực tế trên phần cứng |
| :--- | :--- | :--- |
| **Môi trường đo** | Thuần toán học trong bộ nhớ RAM, biến số được lập trình sẵn | Phòng lab chuyên dụng, lồng Faraday chống nhiễu điện từ |
| **Thiết bị sử dụng** | Trình thông dịch Python, thư viện `random` | Máy hiện sóng băng thông cao (Oscilloscope $\ge 1 \text{ GHz}$), que đo trường gần (EM Probe), súng bắn laser, thiết bị glitch xung nhịp/nguồn |
| **Tín hiệu & Nhiễu** | Tín hiệu sạch, nhiễu giả lập nhân tạo theo phân phối Gaussian đơn giản | Nhiễu môi trường, xung đồng hồ hệ điều hành, can thiệp từ các nhân vi xử lý khác, suy hao tín hiệu cáp đo |
| **Độ trễ & Căn chỉnh (Trigger & Alignment)** | Biết chính xác thời điểm thực thi của từng lệnh | Phải căn chỉnh tín hiệu cực kỳ phức tạp (dùng Cross-Correlation, Dynamic Time Warping - DTW) do hiện tượng lệch pha (Jitter) |
| **Cơ chế phòng thủ** | Không có cơ chế phòng thủ vật lý | Chip phần cứng có cảm biến điện áp, cơ chế Masking ngẫu nhiên hóa, Shuffling lệnh, làm trễ giả (Dummy cycles), tập lệnh phần cứng AES-NI |

---

## 11. Liên hệ các hướng tấn công Tuần 3 và giới hạn áp dụng
Dựa trên kết quả thực nghiệm bảng sai phân DDT và bảng tuyến tính LAT (`experiments/toy_cryptanalysis.py`), nhóm đối chiếu khả năng áp dụng lên AES chuẩn:

### 1. Phân tích vi sai (Differential Cryptanalysis)
- Bảng DDT của S-box AES cho thấy sai phân cực đại chỉ là $4/256 = 2^{-6}$.
- Nhờ cấu trúc *Wide Trail Design*, bất kỳ đặc trưng vi sai nào đi qua 4 vòng liên tiếp đều phải kích hoạt ít nhất 25 hộp S-box.
- Xác suất sai phân toàn cục qua 4 vòng nhỏ hơn $(2^{-6})^{25} = 2^{-150}$. Con số này nhỏ hơn rất nhiều so với xác suất vét cạn $2^{-128}$. Vì vậy, AES với 10, 12, hoặc 14 vòng là **miễn nhiễm tuyệt đối** trước tấn công vi sai thuần túy.

### 2. Phân tích tuyến tính (Linear Cryptanalysis)
- Độ lệch tuyến tính cực đại của S-box trong bảng LAT là $\epsilon = 16/256 = 2^{-4}$.
- Tương tự như vi sai, qua 4 vòng với ít nhất 25 S-box tích cực, độ lệch tuyến tính giảm xuống dưới $2^{24} \cdot (2^{-4})^{25} = 2^{-76}$. Số lượng bản rõ đã biết cần thiết để khai thác vượt quá $2^{150}$ khối, vượt qua kích thước toàn bộ không gian dữ liệu $2^{128}$.

### 3. Tấn công khóa liên quan (Related-Key Attack)
- Tấn công này dựa trên giả định kẻ tấn công có thể quan sát được quá trình mã hóa dưới hai khóa có quan hệ toán học biết trước ($K_A \oplus K_B = \Delta K$).
- Trong thực tế, các hệ thống an toàn luôn sử dụng hàm dẫn xuất khóa chuẩn (như HKDF, PBKDF2) kết hợp với Salt ngẫu nhiên, khiến giả định về "khóa liên quan" không thể xảy ra trong các giao thức an toàn.

### 4. Tấn công Biclique (Biclique Attack)
- Được công bố năm 2011 bởi Bogdanov, Khovratovich và Rechberger. Đây là tấn công đầu tiên trên lý thuyết phá vỡ AES đầy đủ nhanh hơn vét cạn.
- **Độ phức tạp thực tế:**
  - AES-128: $2^{126.1}$ (nhanh hơn vét cạn khoảng 3.8 lần).
  - AES-192: $2^{189.7}$ (nhanh hơn khoảng 5 lần).
  - AES-256: $2^{254.4}$ (nhanh hơn khoảng 4 lần).
- **Giới hạn:** Mặc dù được công nhận là một bước tiến học thuật (cryptanalytic break), độ phức tạp $2^{126.1}$ vẫn đòi hỏi $10^{37}$ phép tính, hoàn toàn không thể thực hiện được trong đời thực. AES vẫn duy trì độ an toàn thực tiễn tuyệt đối.

---

## 12. Bảng so sánh tổng hợp các hướng tấn công

| Hướng tấn công | Nguyên lý cơ bản | Điều kiện cần | Mục tiêu | Độ phức tạp / Mức độ khả thi trên AES chuẩn | Biện pháp phòng chống |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Brute-Force (Vét cạn)** | Thử toàn bộ không gian khóa $\{0, 1\}^k$ | Có ít nhất 1 cặp bản rõ - bản mã $(P, C)$ | Khôi phục khóa bí mật $K$ | **$2^{128} \to 2^{256}$ phép tính**.<br>Hoàn toàn bất khả thi. | Sử dụng độ dài khóa chuẩn $\ge 128$-bit. |
| **Differential (Vi sai)** | Theo dõi độ lệch xác suất của sai phân $\Delta P \to \Delta C$ | Chọn bản rõ (CPA), lượng mẫu cực lớn ($> 2^{128}$) | Khôi phục khóa vòng | **Không khả thi** trên AES đầy đủ (chỉ áp dụng được tối đa 4-5 vòng rút gọn). | Thiết kế Wide Trail Strategy, bảo đảm số lượng S-box kích hoạt lớn. |
| **Linear (Tuyến tính)** | Xấp xỉ quan hệ tuyến tính giữa bit của $P, C$ và $K$ | Biết bản rõ (KPA), lượng mẫu cực lớn ($> 2^{128}$) | Khôi phục bit khóa | **Không khả thi** trên AES đầy đủ (chỉ áp dụng được trên vòng rút gọn). | Tối ưu bảng S-box để đạt độ lệch tuyến tính cực tiểu. |
| **Related-Key** | Khai thác tính yếu trong Key Schedule khi biết quan hệ giữa 2 khóa | Kẻ tấn công kiểm soát hoặc chọn được $\Delta K$ | Tìm khóa bí mật | **Chỉ khả thi trên lý thuyết** đối với AES-192/256 (đòi hỏi $2^{99} - 2^{176}$ dữ liệu). | Dùng KDF chuẩn (PBKDF2, Argon2, HKDF) để sinh khóa độc lập. |
| **Biclique** | Mở rộng Meet-in-the-Middle chia khối AES thành các biclique độc lập | Toàn bộ không gian dữ liệu và tính toán lớn | Phục hồi khóa nhanh hơn vét cạn | **$2^{126.1}$ (AES-128)**.<br>Ý nghĩa thuần lý thuyết, không có khả năng khai thác thực tế. | Không cần thay đổi do độ phức tạp vẫn nằm ngoài năng lực tính toán. |
| **Side-Channel (CPA / Timing)** | Khai thác rò rỉ vật lý (công suất, thời gian, bức xạ điện từ) | Tiếp cận thiết bị hoặc cùng chia sẻ phần cứng/cache | Khôi phục trực tiếp từng byte khóa | **Cực kỳ nguy hiểm** trên phần cứng không được bảo vệ (đặc biệt là chip IoT/Smartcard). | Lập trình Constant-Time, dùng tập lệnh AES-NI, cơ chế Masking/Shuffling. |
| **Fault Attack (DFA)** | Cố tình gây lỗi vật lý (xung nguồn, laser) tại vòng 8-9 | Tiếp cận phần cứng thiết bị trong lúc đang tính toán | Khôi phục khóa vòng cuối | **Cực kỳ nguy hiểm** nếu kẻ tấn công tiếp cận được bo mạch. | Thiết kế mạch kiểm tra dư thừa (Dual execution), cảm biến phát hiện sụt áp/ánh sáng. |
| **Tampering (Bit-Flipping)** | Chỉnh sửa bit bản mã trên đường truyền dữ liệu | Can thiệp vào kênh truyền dữ liệu (MitM) | Sửa đổi nội dung bản rõ giải mã | **Rất dễ thực hiện** nếu sử dụng chế độ không xác thực (ECB, CBC, CTR). | Bắt buộc sử dụng chế độ xác thực liên kết **AEAD (AES-GCM)** hoặc Encrypt-then-MAC. |

---

## 13. Đề xuất biện pháp bảo mật khi triển khai AES
Để đảm bảo an toàn tuyệt đối khi ứng dụng AES trong các hệ thống thông tin thực tế, cần tuân thủ nghiêm ngặt các nguyên tắc sau:

1. **Quản lý khóa (Key Management):**
   - Sinh khóa bằng bộ sinh số ngẫu nhiên an toàn mật mã (CSPRNG, ví dụ `os.urandom()` hoặc `/dev/urandom`).
   - Lưu trữ khóa trong phần cứng chuyên dụng: Mô-đun bảo mật phần cứng (HSM), chip TPM hoặc các dịch vụ quản lý khóa tin cậy (AWS KMS, Azure Key Vault).
   - Thiết lập chính sách xoay vòng khóa định kỳ (Key Rotation) và chính sách hủy khóa an toàn.
2. **Lựa chọn chế độ hoạt động (Mode Selection):**
   - **Tuyệt đối không sử dụng ECB** trong bất kỳ trường hợp nào liên quan đến dữ liệu người dùng hoặc truyền thông mạng.
   - **Ưu tiên hàng đầu các chế độ AEAD (Authenticated Encryption with Associated Data)** như **AES-GCM** hoặc **ChaCha20-Poly1305** để vừa bảo mật vừa xác thực tính toàn vẹn.
   - Nếu bắt buộc dùng CBC hoặc CTR, phải áp dụng mô hình **Encrypt-then-MAC** (kết hợp với HMAC-SHA256) để chống tấn công sửa đổi và tấn công Padding Oracle.
3. **Quản lý Nonce và Vector khởi tạo (IV):**
   - Đối với **CBC**: IV phải được sinh ngẫu nhiên bằng CSPRNG cho mỗi lần mã hóa; không bao giờ dùng IV cố định.
   - Đối với **CTR và GCM**: **Tuyệt đối không tái sử dụng Nonce/Counter với cùng một khóa**. Việc tái sử dụng Nonce trong GCM sẽ phá vỡ hoàn toàn tính bí mật của khóa GHASH và cho phép kẻ tấn công giả mạo bản tin tùy ý.
4. **Bảo vệ chống rò rỉ kênh kề (Side-Channel Hardening):**
   - Luôn sử dụng hàm so sánh chuỗi thời gian cố định (Constant-Time comparison như `hmac.compare_digest`).
   - Tận dụng tập lệnh phần cứng chuyên dụng có sẵn trên CPU hiện đại (**Intel/AMD AES-NI, ARM Cryptography Extensions**) để thực hiện mã hóa trong các chu kỳ máy cố định, loại bỏ hoàn toàn các bảng tra S-box trong bộ đệm (chống cache attack).
   - Áp dụng kỹ thuật Masking (mặt nạ ngẫu nhiên) và chèn chu kỳ rỗng (Dummy cycles) trên các vi điều khiển nhúng.

---

## 14. Phân tích giới hạn của chương trình nghiên cứu
Dự án được xây dựng với mục tiêu sư phạm và nghiên cứu học thuật, do đó có các giới hạn cốt lõi so với hệ thống mật mã sản phẩm:
- **Hạn chế của môi trường Python thuần:**
  - Ngôn ngữ thông dịch bậc cao không thể kiểm soát việc cấp phát thanh ghi hay thời điểm truy cập bộ đệm của CPU, dẫn đến nguy cơ rò rỉ thời gian và cache.
  - Tốc độ thực thi chậm hơn từ 50 - 200 lần so với các thư viện viết bằng C/Assembly tối ưu hóa phần cứng (như OpenSSL, BoringSSL, libsodium).
- **Mô phỏng mang tính trừu tượng:** Các bài thí nghiệm CPA, Cache và DFA sử dụng dữ liệu nhân tạo và giả định lý tưởng hóa nhằm minh họa cơ chế, không thể dùng trực tiếp để khai phá lỗ hổng phần cứng ngoài đời thực.
- **Thiếu kiểm toán bảo mật (Security Audit):** Mã nguồn chưa được thẩm định độc lập theo tiêu chuẩn quốc tế FIPS 140-2 / FIPS 140-3 hoặc Common Criteria (EAL).
- **Khuyến cáo áp dụng:** Chương trình chỉ phục vụ mục đích học tập, giảng dạy và đối chiếu chuẩn thuật toán. Không được sử dụng mã nguồn này trực tiếp trong môi trường sản xuất hoặc bảo vệ dữ liệu nhạy cảm thực tế.

---
*Báo cáo được hoàn thiện và kiểm chứng dựa trên toàn bộ kết quả thực nghiệm của AES Project (Tuần 4).*
