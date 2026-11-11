# Khai báo API và hàm tự cài đặt

Rule mô tả giao diện của một hàm: có bao nhiêu arguments, argument nào chứa key/IV, độ dài buffer được lấy ở đâu, hàm sửa vùng nhớ nào và cách đọc return value. Đây là thông tin do người viết rule cung cấp sau khi đối chiếu prototype hoặc code của hàm.

Rule không tự chứng minh thuật toán thực sự đúng với tên đã khai báo. Nếu gán nhầm prototype hoặc vai trò argument, plugin có thể đọc nhầm dữ liệu.

## 1. Hai cách thêm binding

### Khai báo trong UI

Đặt cursor trong function, chọn **Edit → Plugins → Crypto Probe: Bind current function arguments**, rồi sửa form JSON. Sau khi lưu:

- Quét caller để tính các tham số tại callsite.
- Hoặc dừng tại entry của function để capture khi debug.

Binding này chỉ giữ trong phiên hiện tại. Trạng thái Arm cần được chọn riêng khi muốn bắt breakpoint.

### Lưu thành rule JSON

Copy [custom-api.example](custom-api.example) thành `crypto_probe/rules/z_custom.json`, sửa tên và prototype rồi restart IDA:

```text
crypto_probe/rules/
├── builtin.json
└── z_custom.json
```

`ApiCatalog` đọc các file `.json` theo thứ tự tên. Profile được nạp sau có thể thay profile cùng tên đã nạp trước. Tên có prefix như `__imp_`, `j_` hoặc suffix stdcall `@N` được chuẩn hóa trước khi lookup. File `.example` không được tự nạp.

Rule chỉ chứa dữ liệu JSON; không đặt code Python trong file này.

## 2. Ví dụ hàm nhận raw key và IV

Giả sử đã xác định hàm dưới đây thực hiện XTEA-CBC, sửa buffer `data` tại chỗ và không trả về mã trạng thái:

```c
void my_xtea_cbc(
    uint8_t *data,
    const uint8_t *key,
    const uint8_t *iv,
    size_t size
);
```

Rule đầy đủ:

```json
{
  "schema": 1,
  "apis": [
    {
      "names": ["my_xtea_cbc"],
      "argc": 4,
      "event": "direct",
      "algorithm": "XTEA",
      "mode": "CBC",
      "fields": [
        {"role": "key", "arg": 1, "kind": "bytes", "length": 16},
        {"role": "iv", "arg": 2, "kind": "bytes", "length": 8}
      ],
      "success": "void",
      "writes": [{"arg": 0, "length_arg": 3}]
    }
  ]
}
```

Argument được đánh số từ **0**: data=0, key=1, iv=2, size=3. `key` và `iv` là con trỏ; decoder đọc lần lượt 16 và 8 byte từ địa chỉ đó. `size` là độ dài buffer data, không phải độ dài key.

`writes` báo vùng `data` bị hàm sửa. Static evaluator phải bỏ thông tin cũ của vùng này sau call; nó không tự tính ciphertext chỉ vì đã có binding.

Tên mode phải khớp code đã phân tích. Một hàm TEA/XTEA nhận 16 byte key chưa đủ để kết luận CBC hay ECB.

## 3. Các trường cấp profile

| Trường | Ý nghĩa |
|---|---|
| `names` | Một hoặc nhiều tên function/import dùng chung profile |
| `argc` | Tổng số arguments, từ 0 tới 24 |
| `event` | Chọn cách decoder xử lý lời gọi, ví dụ `direct`, `setkey`, `context_use` |
| `algorithm`, `mode` | Nhãn thuật toán/mode theo thông tin đã xác định; có thể là `unknown` |
| `direction` | `encrypt` hoặc `decrypt` nếu prototype quy định rõ |
| `fields` | Các giá trị cần đọc từ arguments |
| `context_arg` | Index của context/handle để nối nhiều lời gọi |
| `arg_sizes` | Độ rộng scalar khi đọc theo ABI |
| `success` | Điều kiện kiểm tra return value khi debug |
| `writes` | Các vùng nhớ bị hàm sửa để static evaluator invalidate |

Các events EVP, BCrypt/CNG, CryptoAPI, BN/RSA, RNG/KDF có xử lý riêng trong `materials.py` và `runtime.py`. Đổi `event` không tự tạo implementation cho một kiểu API mới. Dùng `direct` cho hàm nhận raw key/IV đơn giản.

## 4. Đọc giá trị trong fields

### Kiểu dữ liệu

| `kind` | Cách đọc |
|---|---|
| `bytes` | Argument là con trỏ tới buffer, cần xác định length |
| `scalar` | Argument là số nguyên, không dereference |
| `pointer` | Giữ địa chỉ; dùng cho các trường có decoder riêng |
| `opaque` | Chỉ giữ tham chiếu object, không đoán layout nội bộ |
| `cstring` | Chuỗi UTF-8 kết thúc bằng NUL trong phần decoder hỗ trợ |
| `utf16` | Chuỗi UTF-16LE kết thúc bằng NUL, dùng cho Windows API |

Ví dụ `uint8_t mask` phải dùng scalar, còn `const uint8_t *key` dùng bytes. Đọc scalar như pointer có thể khiến plugin lấy dữ liệu ở một địa chỉ không liên quan.

### Độ dài buffer

| Khai báo | Cách xác định số byte |
|---|---|
| `length: 16` | Đọc đúng 16 byte |
| `length_arg: 2` | Lấy độ dài từ argument 2 |
| `length_arg: 2, length_divisor: 8` | Argument 2 là số bit, chia 8 để đổi sang byte khi chia hết |
| `length_from: "key_length"` | Lấy thuộc tính key_length đã xác định trong context |

Ví dụ từ profile OpenSSL `AES_set_encrypt_key(userKey, bits, schedule)`:

```json
{
  "role": "key",
  "arg": 0,
  "kind": "bytes",
  "length_arg": 1,
  "length_divisor": 8
}
```

Nếu `bits=256`, decoder cần 32 byte. Nếu không tính được `bits`, không có cơ sở chọn mặc định 16 hay 32 byte. Buffer thực tế được đọc tối đa 64 KiB/field; length ngoài giới hạn hoặc memory chưa biết sẽ không được xuất thành raw key đầy đủ.

### Độ rộng scalar theo ABI

Win64 có pointer và stack slot 8 byte, nhưng `DWORD`, `ULONG` và `int` thường chỉ có 4 byte có nghĩa. Dùng `arg_sizes` để chỉ rõ width, ví dụ:

```json
{"arg_sizes": {"1": 4, "3": 8, "4": "c_long"}}
```

Các key là argument indices, không phải tên tham số. Giá trị hỗ trợ gồm 1, 2, 4, 8 byte hoặc `c_long`. `c_long` theo platform: Win64 là 4 byte, SysV x64 là 8 byte. Pointer/size_t mặc định dùng pointer width của ABI.

`arg_sizes` áp dụng cho danh sách arguments do ABI reader đọc, không thay đổi `fields[].length`. Cần phân biệt độ rộng của một số nguyên length với số bytes của buffer mà số nguyên đó mô tả.

## 5. Quy tắc return value

| `success` | Kiểm tra hiện tại |
|---|---|
| `void` | Không có mã trả về để kiểm tra; xử lý return như đã hoàn thành |
| `bool` | 32 bit thấp khác 0 |
| `openssl` | 32 bit thấp bằng 1 |
| `mbedtls`, `zero` | 32 bit thấp bằng 0 |
| `ntstatus` | 32 bit thấp bằng 0 trong implementation hiện tại |
| `pointer` | Return value khác 0 |
| `positive` | Return value dương sau xử lý signed width của runtime |
| `positive32` | Signed int32 dương |

Đây là các predicates plugin triển khai, không phải quy tắc chung cho mọi hàm của một thư viện. Chọn theo prototype cụ thể. Profile không khai báo `success` có thể dùng fallback của decoder/runtime; khi không có điều kiện cụ thể, không coi metadata success là xác nhận kết quả mã hóa đúng.

Các output như tag, key handle và RNG buffer có xử lý sau return. Cần event/output fields phù hợp; một field `kind: bytes` thông thường được đọc ở input phase không tự trở thành output đã được tạo thành công.

## 6. API tách bước setup key và encrypt

Ví dụ giao diện đơn giản:

```c
void my_aes_setkey(void *ctx, const uint8_t *key);
void my_aes_cbc_encrypt(void *ctx, uint8_t *data, size_t size, const uint8_t *iv);
```

Nếu đã xác định key dài 16 byte và IV dài 16 byte, có thể mô tả hai lời gọi dùng chung `ctx` như sau:

```json
{
  "schema": 1,
  "apis": [
    {
      "names": ["my_aes_setkey"],
      "argc": 2,
      "event": "setkey",
      "algorithm": "AES",
      "mode": "unknown",
      "context_arg": 0,
      "fields": [{"role": "key", "arg": 1, "kind": "bytes", "length": 16}],
      "success": "void"
    },
    {
      "names": ["my_aes_cbc_encrypt"],
      "argc": 4,
      "event": "context_use",
      "algorithm": "AES",
      "mode": "CBC",
      "context_arg": 0,
      "fields": [{"role": "iv", "arg": 3, "kind": "bytes", "length": 16}],
      "success": "void",
      "writes": [{"arg": 1, "length_arg": 2}]
    }
  ]
}
```

Cách này dùng giá trị context để nối raw key quan sát ở `my_aes_setkey` với lần sử dụng sau. Nó không đọc layout của object `ctx`. API tạo handle qua output pointer, import key blob hoặc có cơ chế đổi/reset key cần event và decoder tương ứng, không chỉ thêm context_arg.

## 7. Kiểm tra rule trước khi sử dụng

1. Đối chiếu đúng prototype của phiên bản API hoặc function đã reverse.
2. Kiểm tra argument indices, pointer/scalar và đơn vị bit/byte.
3. Với setup/use API, xác định context hoặc handle nào thực sự nối hai bước.
4. Quét lại caller; xem arguments/length/evidence thay vì chỉ nhìn tên thuật toán.
5. Khi debug, dừng đúng trước call hoặc tại entry, chọn đúng ABI và kiểm tra return metadata.

Nếu API đổi tên, dispatch target chưa xác định hoặc argument được Hex-Rays khôi phục sai, cần sửa phân tích/binding trước. Rule chỉ định cách đọc dữ liệu; nó không khôi phục được dữ liệu không có trong static model hay memory đang debug.
