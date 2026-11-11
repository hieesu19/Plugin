# Crypto Probe

Crypto Probe là plugin IDAPython dùng để nhận diện các hàm mã hóa/giải mã trong binary và phân tích tham số của chúng, gồm **key, IV, nonce, counter, AAD và authentication tag**.

Plugin xử lý hai trường hợp:

- **Chương trình sử dụng API mã hóa có sẵn**, ví dụ `EVP_EncryptInit_ex` của OpenSSL hoặc `BCryptEncrypt` của Windows CNG. Plugin đối chiếu prototype của API để xác định vị trí và độ dài từng tham số, sau đó theo dõi các bước khởi tạo key và context.
- **Chương trình tự cài đặt thuật toán**, không dùng các API trên. Plugin tìm những đặc điểm trong phép toán, hằng số và cách truy cập bộ nhớ để đề xuất thuật toán hoặc nhóm thuật toán phù hợp.

Có thể phân tích khi chưa chạy chương trình (**static analysis**) hoặc đọc tham số từ registers và memory của tiến trình đang debug (**dynamic capture**). Kết quả gồm địa chỉ, dấu hiệu nhận diện và trạng thái khôi phục của từng tham số.

**Phiên bản:** 1.3.0 · **Ngôn ngữ:** Python · **License:** [BSD 3-Clause](LICENSE)

## Cài đặt

Cần IDA Pro 9.x và IDAPython dùng Python 3.9 trở lên. Bản 1.3.0 đã được kiểm tra trên IDA Pro 9.1 với Hex-Rays x64. Plugin dùng Python standard library và IDAPython APIs, không cần pip hay kết nối mạng.

Copy cả hai mục sau vào thư mục `plugins` của IDA:

```text
IDA/plugins/
├── crypto_probe_plugin.py
└── crypto_probe/
    ├── __init__.py
    ├── ...
    └── rules/builtin.json
```

Restart IDA, mở binary và đợi auto-analysis hoàn tất. Output sẽ có dòng `[Crypto Probe] Offline plugin ready`. Mở bảng kết quả tại **Edit → Plugins → Crypto Probe (offline)**.

Hex-Rays cần phù hợp với kiến trúc binary để phân tích data flow từ mã giả. Nếu thiếu decompiler, plugin vẫn đọc được instructions, API callsites và constant tables, nhưng khả năng khôi phục tham số static sẽ hạn chế hơn.

Khi cập nhật, thay cả loader `crypto_probe_plugin.py` và package `crypto_probe/`, rồi restart IDA.

## Cách sử dụng

### Quét static

| Phím | Phạm vi |
|---|---|
| **Ctrl+Alt+J** | Hàm đang đặt cursor; có lần qua wrapper trong giới hạn của interpreter |
| **Ctrl+Alt+R** | Hàm đang đặt cursor và các hàm con theo call graph |
| **Ctrl+Alt+K** | Toàn bộ functions trong database |

Nếu phím tắt trùng plugin khác, dùng action tương ứng trong **Edit → Plugins**.

Với quét đệ quy, hàm gốc ở tầng 0. Nhập `3` để phân tích tới tầng 3; nhập `0` để đi hết các tầng có thể xác định được:

```text
main                    tầng 0
└── process_folder      tầng 1
    └── process_file    tầng 2
        └── encrypt     tầng 3
```

Plugin duyệt các đích gọi hàm đã xác định từ disassembly và một số địa chỉ hàm được dùng làm function pointer. Indirect call chưa resolve có thể bị bỏ sót. Mỗi lượt giới hạn 2.048 functions; Esc hủy và giữ kết quả đã thu thập.

Độ sâu quét function và độ sâu tính giá trị tham số là hai giới hạn riêng. Tìm thấy `encrypt` không có nghĩa đã khôi phục được toàn bộ dữ liệu truyền vào nó. Constant tables và PEM trong data vẫn được quét ở cấp database, kể cả khi quét một function.

### Ví dụ: phân tích AES qua OpenSSL

Đoạn dưới minh họa lời gọi hàm mà plugin phân tích, không phải chương trình C hoàn chỉnh:

```c
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
```

`EVP_EncryptInit_ex` là API khởi tạo mã hóa của OpenSSL. Với descriptor `EVP_aes_256_cbc()`, plugin xác định AES-256-CBC và kiểm tra:

- Argument 0: `ctx`, context dùng để nối các bước khởi tạo và sử dụng thuật toán.
- Argument 3: con trỏ `key`, cần đọc 32 byte.
- Argument 4: con trỏ `iv`, cần đọc 16 byte.

Nếu biết địa chỉ và đủ bytes của hai buffer, static analysis có thể xuất key/IV. Nếu key được tạo từ dữ liệu chỉ có lúc chạy, cần capture tại callsite này hoặc bước setup tương ứng. **Callsite** là địa chỉ instruction gọi hàm, chẳng hạn `call EVP_EncryptInit_ex`.

Với hàm tự cài đặt, kết quả có thể chỉ là `TEA-family` hoặc `ChaCha-family`. Để kết luận variant, mode và vai trò tham số, cần xem thêm cấu trúc code hoặc khai báo binding.

### Đọc kết quả

Double-click một dòng để xem JSON chi tiết. Địa chỉ trong cửa sổ này hiển thị dạng hex, ví dụ `0x140001abc`; dùng `G` trong IDA để nhảy tới địa chỉ đó.

Chuột phải trong bảng để lọc, copy key/IV, nhảy tới code, Arm capture hoặc export. Ví dụ từ khóa lọc: `aes cbc`, `rsa`, `debug`, `key`.

| Trường | Ý nghĩa |
|---|---|
| `algorithm`, `mode` | Thuật toán và mode đã nhận diện; chưa xác định thì giữ `unknown` |
| `source` | `static` hoặc `debug` |
| `confidence` | Loại bằng chứng: API, instruction, table, cấu trúc code hoặc candidate; không phải phần trăm chính xác |
| `evidence` | Địa chỉ và dấu hiệu dùng để đưa ra nhận định |
| `materials` | Giá trị key/IV/nonce/tag/RSA numbers cùng độ dài và trạng thái |
| `diagnostics` | Phần chưa phân tích được, lỗi hoặc giới hạn đã chạm |

Các trạng thái thường gặp trong `materials`:

| Status | Ý nghĩa |
|---|---|
| `recovered` | Khôi phục từ static analysis |
| `observed` | Đọc từ process khi debug |
| `partial` | Chỉ biết một phần bytes |
| `pointer_only` | Chỉ xác định được địa chỉ object |
| `unresolved` | Chưa xác định đủ giá trị, độ dài hoặc vai trò |
| `output_pending` | Chưa đọc output vì cần đợi API return |

Một table hit chỉ cho biết có dãy bytes trùng fingerprint. Finding có `candidate` là gợi ý cần kiểm tra thêm. Cả hai chưa đủ để dùng làm cấu hình giải mã.

### Capture khi debug

1. Quét vùng code chứa bước setup key và encrypt/decrypt.
2. Cấu hình debugger, executable và arguments trong IDA.
3. Chọn một dòng → **Arm selected API callsite**, hoặc dùng **Arm known API callsites**. Giới hạn tự Arm là 512 callsites.
4. Start/Continue bằng IDA. Khi breakpoint dừng, xem findings có `Source=debug`; dùng F9 để chạy tiếp.
5. Chọn **Disarm capture / owned breakpoints** khi kết thúc.

Plugin đọc key/IV **trước khi API thực thi**, và đọc output như random bytes, key handle hoặc tag **sau return** theo profile của API. Cách này giữ được IV ban đầu ngay cả khi API sửa buffer IV.

**Ctrl+Alt+L** dùng để capture thủ công khi process đang suspended tại instruction gọi hàm hoặc entry của hàm đã có binding. Dừng giữa function có thể làm sai vị trí arguments vì registers và stack đã thay đổi.

Nếu attach sau bước setup key, opaque handle thường không đủ để lấy raw key. Cần bắt sớm hơn và chạy lại bước setup. Có thể chọn calling convention bằng **Choose debugger ABI**. Hiện có adapters cho Win64, SysV x64, x86 cdecl/stdcall/fastcall, AArch64 và ARM32; live capture đã được kiểm tra trên Win64.

Plugin không tự Continue/Step. Disarm chỉ dọn breakpoint thuộc quyền quản lý của plugin; breakpoint đã có của người dùng được giữ nguyên theo cơ chế ownership.

### Thuật toán và API được nhận diện

| Nhóm | Cơ chế hỗ trợ |
|---|---|
| AES-128/192/256 | API cho ECB/CBC/CTR/CFB/OFB/GCM; AES instructions và S-box fingerprints |
| DES | API cho ECB/CBC/CFB/OFB; constant tables |
| RSA | API, PEM/DER PKCS#1/PKCS#8/SPKI và documented CNG/CryptoAPI key blobs |
| RC4 | Setup/use APIs và đặc điểm KSA/PRGA |
| Salsa20, ChaCha20 | API; cấu trúc add–rotate–XOR và shared constants |
| XChaCha20, ChaCha20-Poly1305, XChaCha20-Poly1305 | Các API tương ứng; layout key/nonce/AAD/tag theo profile |
| TEA/XTEA/XXTEA | Hằng số, phép shift, key indexing và mixing; biến thể chưa đủ dấu hiệu giữ dạng candidate |
| Biến đổi byte | XOR, add, sub, rotate và một số pattern SSE/AVX |
| RNG/KDF | Theo dõi output của RAND_bytes, getrandom, BCryptGenRandom và PBKDF2 tới nơi sử dụng |

Catalog hiện có **109 profiles / 127 tên API**, gồm OpenSSL, mbedTLS, libsodium, Nettle, tiny-AES và Windows BCrypt/CNG/CryptoAPI. Xem [API coverage](docs/API_COVERAGE.md) để biết chính xác từng tham số và các trường hợp chưa xử lý.

### Binding và export

Với hàm tự cài đặt đã xác định prototype, dùng **Bind current function arguments** để khai báo argument nào là key/IV và độ dài tương ứng. Sau đó quét caller hoặc capture tại function entry. Binding trong UI chỉ giữ trong phiên hiện tại; rule JSON trong `crypto_probe/rules/` được nạp lại khi mở IDA. Hướng dẫn và ví dụ: [RULES.md](docs/RULES.md).

**Export full report** lưu JSON. **Export selected Crypto draft** tạo cấu hình nháp từ một finding để dùng với module Crypto của CyberDesk. Draft còn cần kiểm tra padding, header/trailer, input/output paths và layout counter. XChaCha có thể được nhận diện nhưng chưa có mapping thuật toán tương ứng trong Crypto draft exporter.

## Cấu trúc project

Plugin viết bằng Python. Lớp nối với IDA đọc disassembly và Hex-Rays ctree, rồi chuyển thành biểu diễn trung gian (IR) riêng để phân tích. Các bộ nhận diện, memory model và API decoder dùng chung một định dạng kết quả; UI và exporter đọc định dạng này.

```text
CryptoProbe/
├── crypto_probe_plugin.py       IDA plugin entry point
├── crypto_probe/
│   ├── ui.py                    Controller, actions, bảng kết quả
│   ├── ida_adapter.py           Đọc IDA và chuyển ctree thành IR
│   ├── callgraph.py             Xác định phạm vi quét đệ quy
│   ├── scanner.py               Điều phối nhận diện và phân tích tham số
│   ├── ir.py                    Expr, Stmt, FunctionIR
│   ├── interpreter.py           Partial evaluator cho data flow
│   ├── memory.py                Known/unknown bytes, pointers, objects
│   ├── semantics.py             Chuẩn hóa phép toán và helper nhỏ
│   ├── forwarding.py            Truyền vai trò tham số qua wrapper mỏng
│   ├── literals.py              Decode C string literals
│   ├── simd.py                  Các SIMD operations đã mô hình hóa
│   ├── vector_patterns.py       Nhận diện broadcast/rotate vector
│   ├── apis.py                  Load/validate profiles và cipher descriptors
│   ├── rules/builtin.json       API profiles có sẵn
│   ├── structural.py            Nhận diện từ cấu trúc code
│   ├── signatures.py            Constant fingerprints
│   ├── rsa.py                   ASN.1/PEM/DER/key blob parsing
│   ├── materials.py             Giải nghĩa tham số và theo dõi context
│   ├── abi.py                   Registers/stack theo calling convention
│   ├── debugger.py              DBG_Hooks và breakpoints
│   ├── runtime.py               Capture trước call và xử lý sau return
│   ├── model.py                 Finding, Evidence, Material, ScanResult
│   ├── exporter.py              JSON draft và Markdown formatter
│   ├── __init__.py              Version
│   └── LICENSE
├── docs/
│   ├── DESIGN.md                Kiến trúc và luồng dữ liệu
│   ├── API_COVERAGE.md          Danh sách profiles, lengths và return rules
│   ├── RULES.md                 Cách khai báo API/hàm riêng
│   ├── SOURCES.md               Tài liệu tham chiếu
│   └── custom-api.example       Rule mẫu
├── README.md
├── LICENSE
└── .gitignore
```

Các phần kỹ thuật chính:

- **IR và partial evaluation:** theo dõi phép toán, buffer, giá trị trả về và function pointer trong phạm vi hỗ trợ; gộp các nhánh chưa biết thay vì chọn tùy ý một key.
- **Context tracking:** nối key setup với lần encrypt/decrypt dùng cùng context hoặc handle, tách riêng các key objects.
- **Runtime capture:** giải mã arguments theo ABI, phân biệt trước call với function entry, đọc output sau return và theo dõi thread/process generation.
- **Rule-based API decoding:** khai báo prototype và roles trong JSON để thêm API mà không sửa UI.

Luồng xử lý, ví dụ từng bước và các lựa chọn thiết kế nằm trong [DESIGN.md](docs/DESIGN.md).

## Giới hạn và xử lý lỗi

| Trường hợp | Cách kiểm tra |
|---|---|
| Import error | Loader và folder package phải cạnh nhau; xem traceback trong Output |
| Có algorithm nhưng thiếu key | Kiểm tra prototype trong F5, độ dài buffer và diagnostics; thử capture trước bước setup |
| Hàm con đã quét nhưng arguments vẫn unknown | Kiểm tra data flow của caller, indirect target và các nhánh return |
| Chỉ có AES instruction/S-box hoặc ChaCha-family | Xem thêm round schedule, state layout và cách nối các block để xác định variant/mode |
| Chỉ có RSA public PEM | Chỉ đọc được public numbers; PEM không cho biết padding/OAEP hash của ciphertext |

Static analysis dựa trên ctree của Hex-Rays và các phép toán đã mô hình hóa. Packed code, control flow chưa hỗ trợ, custom VM, SIMD phức tạp hoặc mã giả mất producer sau optimization có thể để lại giá trị unknown. Plugin không suy ngược raw key từ mọi expanded key schedule hoặc opaque object.

Giới hạn mặc định: 2.048 functions cho recursive scan; 12.000 bước IR/root và tối đa 1.024 vòng lặp; wrapper thông thường 3 tầng; getter return-value flow tối đa 64 tầng, vẫn chịu budget và phạm vi quét. Data scan tối đa 128 MiB, đọc buffer tối đa 64 KiB/field. Hết giới hạn hoặc hủy quét sẽ cho kết quả partial.

DES-CTR tự cài đặt cần binding; DES-GCM không được hỗ trợ. Capture ASLR áp dụng cho module chính; DLL mới, JIT và child process cần chọn đúng code/process để phân tích.
