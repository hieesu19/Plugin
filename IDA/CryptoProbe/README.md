# Crypto Probe — IDA plugin chạy offline

Crypto Probe hỗ trợ xác định vị trí code crypto, nhận diện thuật toán, lần nguồn tham số và đọc **key / IV / nonce / counter / AAD / tag / RSA numbers** khi có đủ bằng chứng. Plugin có hai nhánh: phân tích static từ IDA database/Hex-Rays và capture dữ liệu thật khi debug.

Phiên bản source: **1.3.0**. Plugin hoạt động độc lập với CyberDesk.

## Cài đặt và sử dụng

### Yêu cầu

- **IDA Pro 9.x + IDAPython, Python ≥ 3.9**. Phiên bản 1.3.0 đã được kiểm chứng trước đó trên IDA Pro 9.1 với Hex-Rays x64; các môi trường khác cần kiểm tra tương thích.
- Hex-Rays phù hợp với kiến trúc binary giúp lần tham số và dựng lại buffer. Khi thiếu decompiler, plugin vẫn có thể tìm API callsite, instructions và constant tables; khả năng data flow sẽ hạn chế hơn.
- Debug capture cần debugger của IDA có thể đọc registers và memory của target. Plugin chạy bằng Python bên trong IDA đang mở; IDA Windows không dùng venv Python của WSL.
- Runtime chỉ dùng **Python standard library và IDAPython APIs**. Không cần pip, Internet, YARA, MCP hoặc app CyberDesk đang chạy.

### Cài vào IDA

Copy **hai mục cạnh nhau** vào thư mục `plugins` mà bản IDA của bạn đang dùng:

```text
IDA/plugins/
├── crypto_probe_plugin.py
└── crypto_probe/
    ├── __init__.py
    ├── ...
    └── rules/
        └── builtin.json
```

Không chỉ copy loader `.py`; loader cần package `crypto_probe/` đi kèm. README và `docs/` dành cho người đọc, không bắt buộc copy vào IDA.

Restart IDA, mở binary và chờ auto-analysis. Output sẽ có thông báo `[Crypto Probe] Offline plugin ready`. Mở bảng tại **Edit → Plugins → Crypto Probe (offline)**.

Khi cập nhật, copy đè cả loader và package, rồi restart IDA để tránh dùng lẫn module Python của hai phiên bản.

### Quét static

| Phím / thao tác | Chức năng |
|---|---|
| **Ctrl+Alt+J** | Quét function đang đặt cursor; có bounded wrapper evaluation |
| **Ctrl+Alt+R** | Quét function hiện tại và các function con đệ quy |
| **Ctrl+Alt+K** | Quét toàn database |
| Double-click dòng kết quả | Mở JSON chi tiết, evidence và materials |
| Chuột phải → Filter results | Lọc, ví dụ `aes cbc`, `rsa`, `debug`, `key` |
| Chuột phải → Jump to selected address | Nhảy tới địa chỉ của finding |
| Chuột phải → Copy selected key / private d | Copy vật liệu key/private exponent đã có |
| Chuột phải → Copy selected nonce / IV | Copy nonce hoặc IV đã có |

Nếu hotkey trùng plugin khác, dùng action tương ứng trong **Edit → Plugins**.

Với recursive scan, nhập **`0` để đi hết các tầng tới được**; nhập `3` để lấy root ở tầng 0 và các function con tới tầng 3:

```text
main                 tầng 0
└── process_folder   tầng 1
    └── process_file tầng 2
        └── encrypt  tầng 3
```

Mỗi function trong scope được kiểm tra pattern/API. Discovery dựa trên các target xác định được qua code references/imports/tail calls và những address-taken targets có thể tìm thấy; indirect call chưa resolve có thể bị bỏ sót. Giới hạn hiện tại là **2.048 functions/lượt**. Esc/Cancel giữ lại kết quả partial và diagnostics.

Độ sâu call graph khác độ sâu lần giá trị. Dù quét được function crypto sâu, key vẫn có thể unresolved nếu đường sinh key vượt khả năng interpreter. Các lượt quét cũng giữ phần dò constant/PEM trong data của database; data finding không tự chứng minh root function sử dụng dữ liệu đó.

### Đọc kết quả

Bảng hiển thị **Address, Function/API, Algorithm, Mode, Confidence, Source, Materials**. Double-click để xem chi tiết; các trường địa chỉ trong JSON có dạng `0x140001abc`, có thể copy vào phím `G` của IDA. Length/counter/scalar vẫn là số, giá trị chưa biết là `null`.

| Trường | Cách hiểu |
|---|---|
| `algorithm`, `mode` | Thuật toán/mode đã có evidence; `unknown` nếu chưa xác định |
| `source` | `static` hoặc dữ liệu quan sát khi `debug` |
| `confidence` | Loại bằng chứng, không phải phần trăm chính xác |
| `evidence` | Địa chỉ và lý do nhận diện: API, instruction, structure, table, format… |
| `materials` | Key/IV/nonce/tag/RSA numbers cùng độ dài, giá trị và trạng thái |
| `diagnostics` | Unsupported flow, cancellation, hết budget hoặc lỗi phân tích |

Các confidence thường gặp: `api_contract`, `instruction_match`, `table_match`, `format_match`, `structural_match`, `candidate`.

Các trạng thái materials:

- `recovered`: static analysis khôi phục được giá trị.
- `observed`: đọc được từ process đang debug.
- `partial`: mới biết một phần bytes.
- `pointer_only`: có địa chỉ object nhưng chưa có raw bytes.
- `unresolved`: chưa đủ dữ liệu hoặc chưa chứng minh được length/role.
- `output_pending`: cần chờ API return để đọc output.

Nhận ra thuật toán không đồng nghĩa lấy được key. Constant table không phải key. Plugin giữ byte chưa biết dưới dạng unknown, không tự điền zero thành key hoàn chỉnh.

### Capture key / IV / nonce khi debug

1. Quét caller/phạm vi cần xem để plugin tạo API bindings.
2. Cấu hình debugger và arguments bằng IDA bình thường.
3. Chọn **Arm selected API callsite** hoặc **Arm known API callsites**. Nên bắt đầu với một phạm vi nhỏ; giới hạn tự Arm là 512 callsites.
4. Start/Continue bằng IDA. Plugin bắt trước call để đọc input và sau return để đọc output/return status.
5. Xem finding có `Source=debug`; dùng F9 khi muốn tiếp tục.
6. Chọn **Disarm capture / owned breakpoints** khi xong.

**Ctrl+Alt+L** capture thủ công tại instruction pointer đang suspended. Dừng đúng call instruction hoặc entry của function đã có API/manual binding. Dừng giữa function có thể không còn arguments ở vị trí ABI ban đầu.

Key/IV được snapshot **trước call**; random buffer, output handle hoặc tag được đọc **sau successful return** theo API contract. Debug capture đọc memory mới từ debugger. Plugin không tự Continue/Step/call function trong target. Disarm chỉ dọn breakpoint plugin sở hữu theo cơ chế ownership.

Nếu attach sau bước setup key, opaque handle có thể không đủ để lấy raw key: cần đặt capture sớm hơn và chạy lại tới API nhận key. Khi ABI tự nhận không đúng, dùng **Choose debugger ABI**. Các adapters hiện có: Win64, SysV x64, x86 cdecl/stdcall/fastcall, AArch64, ARM32; live debugger đã được kiểm chứng trước đó trên Win64.

### Các nhóm thuật toán

| Nhóm | Coverage chính |
|---|---|
| AES-128/192/256 | ECB, CBC, CTR, CFB, OFB, GCM qua API/context; AES instructions và S-box fingerprints |
| DES | ECB, CBC, CFB, OFB; API và table fingerprints |
| RSA | API/context setters; PEM/DER PKCS#1, PKCS#8, SPKI và documented CNG/CryptoAPI key blobs |
| RC4 | Raw-key setup/use APIs; KSA/PRGA structural candidates |
| Salsa20 | API, ARX structure và shared constants |
| ChaCha20 / XChaCha20 | API, nonce/counter layouts và ChaCha-family structural candidates |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | API contracts cho key, nonce, AAD và tag |
| TEA / XTEA / XXTEA | Delta, shifts, index/masks, key accesses; một số biến thể giữ dưới dạng candidate |
| Custom đơn giản | Byte XOR/add/sub/rotate, constant/variable operands và một số SSE/AVX patterns |
| Producer RNG/KDF | Theo output từ PBKDF2, RAND_bytes, getrandom, BCryptGenRandom tới consumer |

Có **109 API profiles / 127 tên API**, gồm OpenSSL, mbedTLS, libsodium, Nettle, tiny-AES và Windows BCrypt/CNG/CryptoAPI. Chi tiết prototype, argument index và return contract: [API_COVERAGE.md](docs/API_COVERAGE.md).

DES-CTR cần custom binding, chưa có detector tự nhận mode cho code DES-CTR tự viết. DES-GCM không được hỗ trợ. Pattern quarter-round ChaCha/Salsa không tự chứng minh số round hoặc nonce variant. PEM không chứa thông tin padding/OAEP hash của ciphertext; public PEM chỉ có public numbers.

### Export

- **Export full report:** xuất JSON hoặc Markdown để xem đầy đủ findings/evidence/materials.
- **Export selected Crypto draft:** tạo cấu hình nháp từ finding đang chọn để đối chiếu hoặc đưa sang module Crypto của CyberDesk.

Crypto draft cần review: input/output paths, header/trailer, padding, original size, counter layout/endian và các RSA settings chưa có evidence. Export không tự giải mã folder; plugin hoạt động độc lập khi không có CyberDesk.

### Bind hàm riêng / thêm API

Với hàm tự implement đã hiểu prototype, đặt cursor trong function rồi chọn **Bind current function arguments**. Sửa form JSON để chỉ rõ số arguments và vai trò key/IV. Index bắt đầu từ **0**.

Ví dụ khai báo cho prototype `void my_xtea(uint8_t *data, const uint8_t *key, const uint8_t *iv, size_t size)` khi đã xác nhận đây là XTEA-CBC:

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

Rescan **caller** để lấy input static hoặc capture tại entry khi debug. Nếu hàm thực tế không dùng IV, bỏ field đó và khai báo đúng mode. Binding qua UI chỉ giữ trong phiên hiện tại.

Muốn lưu lâu dài, dùng [custom-api.example](docs/custom-api.example) làm mẫu, đặt file `.json` vào `crypto_probe/rules/` rồi restart IDA. Các file được nạp theo thứ tự tên; rule sau có thể override API trùng tên. JSON là cấu hình dữ liệu, không chứa Python để thực thi.

### Giới hạn và xử lý lỗi

- Import error: kiểm tra loader và package ở cạnh nhau, đúng thư mục plugins của IDA đang mở; xem traceback trong Output.
- Không có key static: kiểm tra prototype/F5, length, branch và diagnostics; dùng debug capture trước bước setup nếu cần.
- F5 mất producer/register data flow do optimization, indirect target chưa biết, packed code, obfuscation/custom VM hoặc control flow chưa hỗ trợ có thể để lại unknown.
- Interpreter có budget: khoảng 12.000 bước/root, loop tối đa 1.024 lần, wrapper thông thường tối đa 3 tầng; getter return-value flow có giới hạn riêng tới 64 tầng và vẫn chịu budget/scope.
- Data scan tối đa 128 MiB; capture buffer tối đa 64 KiB/field. Kết quả bị giới hạn/cancel là partial.
- Không suy ra mode chỉ từ AES instruction; không mặc định ChaCha-family là ChaCha20 đầy đủ; không coi mọi byte loop là encryption.
- Scan không tự rename/patch hoặc apply type. Hex-Rays có thể cập nhật biểu diễn/type inference khi decompile. Action **Append algorithm comment** là thao tác riêng để thêm comment.
- Runtime hỗ trợ ASLR của module chính; code JIT, DLL mới hoặc child process cần scope/binding/debug context phù hợp.

## Cấu trúc project

### Công nghệ

Plugin viết bằng **Python**, chạy trong IDAPython. UI dùng native IDA Choose/simplecustviewer/actions. Hex-Rays cung cấp ctree; phần core chuyển ctree thành IR Python để nhận diện và lần giá trị. Rule API dùng JSON. Nhánh debug dùng IDA debugger hooks và ABI adapters. Chi tiết thiết kế: [DESIGN.md](docs/DESIGN.md); nguồn tham khảo: [SOURCES.md](docs/SOURCES.md).

### Sơ đồ thư mục

```text
CryptoProbe/
├── README.md                     Hướng dẫn dùng và kiến trúc
├── LICENSE                       BSD 3-Clause
├── .gitignore                    Bỏ cache, IDB, outputs và private keys
├── crypto_probe_plugin.py        Entry point để IDA load plugin
├── crypto_probe/
│   ├── __init__.py               Phiên bản package
│   ├── ui.py                     Controller, actions, bảng kết quả
│   ├── ida_adapter.py            Đọc IDA / lift Hex-Rays ctree thành IR
│   ├── callgraph.py              Dựng scope đệ quy
│   ├── scanner.py                Điều phối static scan
│   ├── ir.py                     Expr, Stmt, FunctionIR
│   ├── semantics.py              Chuẩn hóa biểu thức và helper nhỏ
│   ├── interpreter.py            Partial evaluation, arguments/return flow
│   ├── memory.py                 Known/unknown bytes, pointers và objects
│   ├── forwarding.py             Truyền key-role qua thin wrappers
│   ├── literals.py               Đọc bytes từ C string literals
│   ├── simd.py                   Concrete SIMD operations
│   ├── vector_patterns.py        Def/use, broadcast và vector rotate patterns
│   ├── apis.py                   Load/validate rules, cipher descriptors
│   ├── rules/builtin.json        API profiles có sẵn
│   ├── structural.py             Nhận diện cấu trúc crypto
│   ├── signatures.py             Constant table fingerprints
│   ├── rsa.py                    PEM/DER/RSA key blob parsing
│   ├── materials.py              Key/IV/nonce roles, contexts và API decoding
│   ├── abi.py                    Registers/stack arguments, return contracts
│   ├── debugger.py               DBG_Hooks và breakpoint ownership
│   ├── runtime.py                Trạng thái trước call / sau return
│   ├── model.py                  Finding, Evidence, Material, ScanResult
│   ├── exporter.py               JSON/Markdown/Crypto draft
│   └── LICENSE                   License của runtime package
└── docs/
    ├── API_COVERAGE.md           Chi tiết API/prototype/roles
    ├── DESIGN.md                 Thiết kế và nguyên tắc giữ evidence
    ├── SOURCES.md                Nguồn tài liệu/repository tham khảo
    └── custom-api.example        Mẫu rule API riêng
```

### Các thành phần nối với nhau như thế nào?

```text
IDA load crypto_probe_plugin.py
             │
             ▼
       ui.Controller ────────────── menu / J / K / R / L
             │
             ├── Static
             │    callgraph + ida_adapter
             │              │
             │              ▼
             │         FunctionIR
             │              │
             │              ▼
             │           scanner
             │           ├── structural / signatures / rsa
             │           └── interpreter + memory
             │                         │
             │                         ▼
             │               materials + API rules
             │
             └── Debug
                  scanner.bindings → debugger → ABI → runtime
                                                     │
                                                     ▼
                                            materials + API rules

Static và Debug → model.ScanResult → UI / JSON / exporter
```

`scanner.py` tạo bindings tại các callsite để debugger biết prototype/roles cần đọc. Hai nhánh dùng chung `materials.py` và API catalog, nhưng nhánh debug đọc bytes mới từ process. Context/handle nối bước setup key/IV với các lần sử dụng sau đó, giữ provenance và setup addresses.

`model.py` là contract chung: `Finding` giữ algorithm/mode/source/confidence, `Evidence` giữ lý do cùng địa chỉ, `Material` giữ bytes/scalar và trạng thái. UI/exporter đọc model đó; đổi cách trình bày không cần thay detector. Chuyển address sang hex chỉ diễn ra lúc trình bày/export.

### Điểm mở rộng

| Muốn thêm gì? | Nơi thực hiện |
|---|---|
| API nhận key/IV theo prototype đã biết | JSON trong `crypto_probe/rules/` |
| Stateful API có kiểu handle/setup mới | Rules và decoder trong `materials.py`/`runtime.py` |
| Pattern thuật toán tự implement | `structural.py`, có thể thêm normalization trong `semantics.py` |
| Constant table mới | `signatures.py` |
| Ctree/helper/SIMD operation chưa hỗ trợ | `ida_adapter.py`, `interpreter.py`, `simd.py` |
| Calling convention mới | `abi.py` |
| Kiểu output mới | `exporter.py`, dùng model hiện có |

Khi mở rộng, giữ rõ evidence quan sát được và giả thuyết; raw key cần đủ bytes/length. Không tăng confidence chỉ vì gặp một hằng số hay tên function có vẻ giống crypto.

Project có thể dùng làm Git repository tại thư mục này; entry point và package đã nằm ở root để copy vào IDA trực tiếp. Giữ các license khi phân phối.
