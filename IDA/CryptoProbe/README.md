# Crypto Probe

Plugin IDA để tìm code crypto, lần nguồn key/IV/nonce và lấy các giá trị này khi debug. Hỗ trợ lời gọi thư viện và một số dạng tự implement như TEA, RC4, ChaCha, XOR byte.

Phiên bản: **1.3.0**.

## Cài đặt

Cần **IDA Pro 9.x**, IDAPython dùng Python 3.9 trở lên. Đã kiểm tra với IDA 9.1 và Hex-Rays x64. Plugin chạy offline trong IDA, không cần cài thêm package Python.

Copy `crypto_probe_plugin.py` và folder `crypto_probe` vào thư mục plugins của IDA:

```text
IDA/plugins/
├── crypto_probe_plugin.py
└── crypto_probe/
    ├── __init__.py
    ├── ...
    └── rules/builtin.json
```

Restart IDA, mở binary và đợi auto-analysis. Trong Output sẽ có dòng `[Crypto Probe] Offline plugin ready`. Mở plugin tại **Edit → Plugins → Crypto Probe (offline)**.

Khi cập nhật, thay cả file `.py` và folder `crypto_probe`, rồi restart IDA.

## Sử dụng

### Quét code

Đặt cursor trong hàm cần xem rồi dùng các phím sau:

| Phím | Chức năng |
|---|---|
| **Ctrl+Alt+J** | Quét hàm hiện tại |
| **Ctrl+Alt+R** | Quét hàm hiện tại và các hàm con đệ quy |
| **Ctrl+Alt+K** | Quét toàn database |
| **Ctrl+Alt+L** | Capture tham số tại vị trí đang dừng khi debug |

Nếu trùng hotkey, chọn action trong **Edit → Plugins**.

Với `Ctrl+Alt+R`, nhập độ sâu muốn quét. Hàm gốc tính là tầng 0; nhập `0` để đi hết các tầng tìm được.

```text
main                 tầng 0
└── process_folder   tầng 1
    └── process_file tầng 2
        └── encrypt  tầng 3
```

Ví dụ trên cần depth `3` để tới `encrypt`. Mỗi lượt giới hạn 2.048 hàm. Indirect call chưa xác định được đích có thể bị bỏ sót; Esc hủy lượt quét và giữ phần kết quả đã có.

Hex-Rays giúp lần tham số và dựng lại buffer key. Nếu không có decompiler phù hợp, vẫn quét được API callsites, instructions và constant tables, nhưng thường không lấy đủ tham số static.

### Xem kết quả

Double-click một dòng để mở JSON chi tiết. Địa chỉ ở cửa sổ này có dạng `0x140001abc`, có thể copy vào `G` của IDA để nhảy tới.

Chuột phải trong bảng để lọc, nhảy tới code, copy key/IV hoặc export. Ví dụ từ khóa lọc: `aes cbc`, `rsa`, `debug`, `key`.

| Trường | Nội dung |
|---|---|
| `algorithm`, `mode` | Thuật toán và mode; `unknown` nếu chưa xác định |
| `source` | Phân tích `static` hay capture từ `debug` |
| `confidence` | Cách nhận diện: API, instruction, table, cấu trúc code… |
| `evidence` | Địa chỉ và dấu hiệu đã tìm thấy |
| `materials` | Key, IV, nonce, counter, AAD, tag hoặc các số RSA |
| `diagnostics` | Lỗi, phần chưa phân tích được hoặc giới hạn đã chạm |

Trong `materials`, xem `status` để biết giá trị đã lấy được tới đâu:

| Status | Ý nghĩa |
|---|---|
| `recovered` | Tính được từ static analysis |
| `observed` | Đọc được khi debug |
| `partial` | Chỉ biết một phần bytes |
| `pointer_only` | Có địa chỉ object, chưa có raw bytes |
| `unresolved` | Chưa lấy được giá trị hoặc chưa xác định độ dài |
| `output_pending` | Cần đợi API return |

Finding có `candidate` cần xem lại code. Một S-box hoặc nhóm phép toán giống crypto chưa đủ để kết luận thuật toán, mode hay key.

### Lấy key khi debug

1. Quét vùng code có bước setup key và encrypt/decrypt.
2. Cấu hình debugger và arguments trong IDA.
3. Chọn dòng cần bắt → **Arm selected API callsite**, hoặc dùng **Arm known API callsites**. Giới hạn tự Arm là 512 callsites.
4. Chạy bằng F9. Khi dừng, xem dòng có `Source=debug`. Bấm F9 để tiếp tục.
5. Chọn **Disarm capture / owned breakpoints** khi xong.

Key/IV được đọc trước call. Random bytes, output handle và tag được đọc sau khi API return thành công. Plugin dùng memory của process đang debug và giữ riêng trạng thái theo thread/handle.

`Ctrl+Alt+L` dùng khi process đang dừng tại call instruction hoặc entry của hàm đã có binding. Nếu dừng giữa hàm, registers/stack có thể đã thay đổi nên đọc arguments sẽ không đúng.

Nếu attach sau khi setup key đã chạy, cần đặt breakpoint sớm hơn rồi chạy lại. Chỉ có opaque handle thường không đủ để lấy raw key.

Plugin không tự Continue/Step. Disarm dọn các breakpoint do plugin tạo; breakpoint có sẵn của người dùng được giữ lại. Có thể chọn calling convention bằng **Choose debugger ABI**. Hiện có adapters cho Win64, SysV x64, x86 cdecl/stdcall/fastcall, AArch64 và ARM32; phần debug đã chạy thực tế trên Win64.

### Các dạng nhận diện

| Nhóm | Hỗ trợ |
|---|---|
| AES-128/192/256 | ECB, CBC, CTR, CFB, OFB, GCM qua API; AES instructions và S-box |
| DES | ECB, CBC, CFB, OFB; API và constant tables |
| RSA | API, PEM/DER PKCS#1/PKCS#8/SPKI, CNG/CryptoAPI key blobs; đọc n/e/d/p/q/CRT nếu có |
| RC4 | API và pattern KSA/PRGA |
| Salsa20 | API, ARX và constants |
| ChaCha20 / XChaCha20 | API, nonce/counter layout; pattern ChaCha-family |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | API có key, nonce, AAD và tag |
| TEA / XTEA / XXTEA | Delta, shifts, masks, index và cách truy cập key |
| Biến đổi byte | XOR, add, sub, rotate; một số pattern SSE/AVX |
| RNG/KDF | Theo output của PBKDF2, RAND_bytes, getrandom, BCryptGenRandom |

Các API được hỗ trợ gồm OpenSSL, mbedTLS, libsodium, Nettle, tiny-AES và Windows BCrypt/CNG/CryptoAPI. Xem từng prototype tại [API_COVERAGE.md](docs/API_COVERAGE.md).

### Export

- **Export full report:** lưu toàn bộ kết quả ra JSON.
- **Export selected Crypto draft:** xuất thông số của dòng đang chọn thành JSON để dùng với module Crypto của CyberDesk.

Crypto draft còn cần điền đường dẫn, padding, header/trailer và các thông số file chưa xác định. Kiểm tra lại counter layout/endian và RSA settings trước khi dùng để giải mã.

### Khai báo hàm riêng

Nếu đã biết prototype của hàm tự implement, đặt cursor trong hàm rồi chọn **Bind current function arguments**. Khai báo số arguments, argument chứa key/IV và độ dài. Index bắt đầu từ 0.

Ví dụ với hàm XTEA-CBC:

```cpp
void my_xtea(uint8_t *data, const uint8_t *key, const uint8_t *iv, size_t size);
```

```json
{
  "names": ["my_xtea"],
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
```

Quét lại caller để lấy tham số static, hoặc dừng ở entry để capture khi debug. Nếu hàm không dùng IV, bỏ field `iv` và sửa mode cho đúng.

Binding trong UI chỉ giữ ở phiên hiện tại. Để dùng lại, lấy [custom-api.example](docs/custom-api.example) làm mẫu, lưu thành `.json` trong `crypto_probe/rules/` rồi restart IDA. Rule được nạp theo thứ tự tên file; file sau có thể ghi đè API trùng tên.

### Khi kết quả thiếu hoặc sai

- **Import error:** kiểm tra file loader và folder package có nằm cạnh nhau không; xem traceback trong Output.
- **Có algorithm nhưng thiếu key:** xem prototype trong F5, độ dài buffer và `diagnostics`. Thử capture ở bước setup key.
- **Quét đệ quy thấy hàm nhưng vẫn thiếu tham số:** tìm được hàm và tính được dữ liệu truyền vào là hai bước riêng. Mã giả bị mất register data flow hoặc nhánh chưa biết có thể khiến key unresolved.
- **Tìm thấy ChaCha/Salsa-family:** cần kiểm tra thêm số round và state layout để biết variant. AES instruction cũng chưa cho biết mode.
- **RSA PEM:** public key chỉ có n/e; PEM không cho biết OAEP hash, MGF1 hash hay label của ciphertext.
- **DES:** chưa tự nhận mode CTR của code tự viết; không hỗ trợ DES-GCM.

Packed code, obfuscation, custom VM, JIT, DLL mới nạp và child process có thể cần xử lý thủ công. Các giới hạn hiện tại:

| Phần | Giới hạn |
|---|---|
| Recursive scan | 2.048 hàm |
| Partial interpreter | Khoảng 12.000 bước/root; loop tối đa 1.024 lần |
| Wrapper thông thường | Tối đa 3 tầng |
| Getter return-value flow | Tối đa 64 tầng, vẫn chịu giới hạn bước và phạm vi quét |
| Data scan | 128 MiB |
| Debug buffer | 64 KiB/field |

## Cấu trúc project

Code viết bằng Python, dùng IDAPython để đọc database và debugger. Hex-Rays ctree được chuyển thành IR riêng trước khi phân tích. UI dùng native IDA `Choose`, `simplecustviewer` và actions; API rules nằm trong JSON.

```text
CryptoProbe/
├── crypto_probe_plugin.py   Loader của IDA
├── crypto_probe/
│   ├── __init__.py          Version
│   ├── ui.py                Menu, hotkeys, bảng kết quả
│   ├── ida_adapter.py       Đọc IDA, chuyển ctree thành IR
│   ├── callgraph.py         Duyệt các hàm được gọi
│   ├── scanner.py           Điều phối static scan
│   ├── ir.py                Expr, Stmt, FunctionIR
│   ├── semantics.py         Chuẩn hóa biểu thức, mở rộng helper nhỏ
│   ├── interpreter.py       Tính giá trị, lần arguments và return
│   ├── memory.py            Bytes, pointers, stack/heap objects
│   ├── forwarding.py        Lần tham số key qua wrapper mỏng
│   ├── literals.py          Đọc C string literals
│   ├── simd.py              Các phép SIMD đã hỗ trợ
│   ├── vector_patterns.py   Pattern broadcast và rotate vector
│   ├── apis.py              Đọc rule, nhận cipher descriptor
│   ├── rules/builtin.json   API profiles
│   ├── structural.py        Pattern cấu trúc code crypto
│   ├── signatures.py        Constant tables
│   ├── rsa.py               Đọc PEM/DER/key blobs
│   ├── materials.py         Đọc key/IV/nonce, quản lý context
│   ├── abi.py               Arguments trong registers/stack
│   ├── debugger.py          Hooks và breakpoints
│   ├── runtime.py           Xử lý trước call / sau return
│   ├── model.py             Finding, Evidence, Material, ScanResult
│   ├── exporter.py          JSON, Markdown, Crypto draft
│   └── LICENSE
├── docs/
│   ├── API_COVERAGE.md
│   ├── DESIGN.md
│   ├── SOURCES.md
│   └── custom-api.example
├── README.md
├── LICENSE
└── .gitignore
```

### Luồng xử lý

```text
crypto_probe_plugin.py → ui.Controller
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
         Static scan                       Debug capture
   callgraph + ida_adapter              bindings từ scanner
              │                                │
              ▼                                ▼
         FunctionIR                     debugger + abi
              │                                │
              ▼                                ▼
           scanner                           runtime
      ┌───────┴────────┐                       │
      ▼                ▼                       │
  structural       interpreter                 │
  signatures        + memory                   │
  rsa                  │                       │
      │                └───────────┬───────────┘
      │                            ▼
      │                   materials + API rules
      │                            │
      └─────────────┬───────────────┘
                    ▼
                ScanResult
                    │
                    ▼
             UI / JSON / exporter
```

`scanner.py` tìm pattern và API callsites, sau đó tạo bindings để debugger biết cần đọc arguments nào. `interpreter.py` lần giá trị static qua phép toán, memory và lời gọi hàm. `materials.py` nối bước setup key/IV với các lần encrypt/decrypt dùng cùng context hoặc handle.

Kết quả dùng chung model trong `model.py`: `Finding` chứa thuật toán và vị trí, `Evidence` chứa dấu hiệu nhận diện, `Material` chứa key/IV và trạng thái đọc. UI và exporter lấy dữ liệu từ model này.

### Thêm tính năng

| Thay đổi | File cần xem |
|---|---|
| Thêm API theo prototype | `rules/*.json` |
| Thêm kiểu setup/context/handle | `materials.py`, `runtime.py` |
| Nhận thuật toán tự implement | `structural.py`, `semantics.py` |
| Thêm constant table | `signatures.py` |
| Hỗ trợ thêm ctree/helper/SIMD | `ida_adapter.py`, `interpreter.py`, `simd.py` |
| Thêm calling convention | `abi.py` |
| Đổi định dạng export | `exporter.py` |

Chi tiết: [thiết kế](docs/DESIGN.md), [API profiles](docs/API_COVERAGE.md), [nguồn tham khảo](docs/SOURCES.md).
