# Thiết kế và bảo toàn evidence

```text
IDB / Hex-Rays ctree / instructions
        │
        ├─ semantic features ──► algorithm / family / candidate
        ├─ constant tables ───► table occurrence
        ├─ PEM/DER/blob ───────► checked format and numbers
        └─ bounded IR evaluator ─► API arguments at each call
                                      │
                               context/handle setup chain
                                      │
                                      ▼
                               findings + evidence
                                      ▲
 debugger regs + fresh memory ─► ABI ─► before call / after return
                                      │
                                      ▼
                            native chooser / JSON / Crypto draft
```

## Core độc lập IDA

`ir.py` giữ structured expressions/statements bằng dataclasses. `ida_adapter.py` tạo IR từ ctree và giữ disassembly fallback. IR không chứa SWIG object/cfunc dangling reference. `scanner.py` quét features và API callsite; evaluator chạy ở crypto API callers, key-candidate callers và wrapper ancestors để tránh emulation CRT không liên quan. Quét current function cho phép wrapper traversal bounded. Callsite chưa evaluate được vẫn đưa vào bảng với unresolved arguments để capture live.

`callgraph.py` dùng BFS/visited để tạo scope recursive trước khi lift IR. `IdaSource.callees()` chỉ đọc code xrefs/import slots, gồm inter-function tail jumps; không gọi Hex-Rays ở discovery. Độ sâu graph độc lập với wrapper evaluation. Recursive scan truyền danh sách functions vào scanner và `restrict_scope=True`; lookup evaluator chỉ trả IR trong danh sách để không vượt scope/depth/budget. Canceled/limited scope và unresolved indirect calls ghi diagnostics cùng metadata.

`interpreter.py` theo dõi scalar, pointer và byte. Có sizeof, signed comparisons/division/casts, integer wrap, shift validity, copy/set, structured branch/loop và wrapper traversal. Pointer stack dùng frame + offset thực từ Hex-Rays, cho phép các biến alias cùng vùng. Low-byte pointer difference có affine/residue model để xử lý optimization như `(BYTE)dst - (BYTE)base`, mà không phải đoán địa chỉ stack.

Không symbolic-execute cả process và không brute-force nhánh. Nhánh unknown chạy hai trạng thái độc lập rồi merge phần bằng nhau; short-circuit/ternary bảo toàn side effects. Loop/budget, unrecognized control flow và unknown calls khiến dữ liệu phụ thuộc trở thành unknown. Primitive crypto đã nhận diện không được emulated để “chứng minh” đầu ra; caller vẫn có snapshot memory **ở trước call** để đọc input key.

`memory.py` có bytes known/unknown và object slots riêng cho symbolic pointer/handle. Không default zero cho byte chưa khởi tạo. Partial bytes không xuất thành raw key. Mọi read buffer phải có độ dài chứng minh và nằm trong limit.

## API contract và state

`rules/builtin.json` khai báo argc, arg roles, fixed/dynamic lengths, integer width, output buffers và return contract. Rule JSON chỉ là dữ liệu. `materials.py` dùng contract để phân biệt raw key, IV, nonce, counter, AAD/tag, RSA n/e/d và opaque object.

Setup context/handle giữ key provenance và setup addresses. BCrypt provider và từng key handle là context khác nhau; tạo key không đổi raw key trên provider. Chỉ các bước có cùng context/handle mới nối vật liệu. Destroy/reset bỏ state. Static return chưa chứng minh success; runtime chỉ commit khi successful return.

`rsa.py` parse bounded ASN.1, xác nhận RSA OID và p*q khi có private factors; đọc documented key blob layouts/endian. Không dereference `RSA*` theo một cấu trúc OpenSSL đoán mò. RSA2 blob có p/q có thể tính d bằng modular inverse; ghi rõ d_derived.

`signatures.py` tạo AES S-box bằng GF(2^8); DES tables và sigma/tau là algorithm constants. Không lấy YARA rules GPL rồi đổi license cho plugin. Một occurrence không tự chứng minh function sử dụng thuật toán/mode tương ứng.

## Debug capture

`abi.py` phân biệt **before-call** và **entry**: return-address slot, Win64 home area, 32-bit scalar widths, x86 uint64 slots và ARM register pair alignment. Wrong ABI có thể đọc sai key nên UI có ABI selector và metadata.

`debugger.py` đọc bằng `ida_idd.dbg_read_memory`, đăng ký DBG_Hooks và quản lý breakpoint ownership. `runtime.py` giữ pending return theo thread/return address. Key/IV snapshot trước call, output/tag đọc sau successful return. Return failures không tạo context mới. Process generation và ASLR delta tách các phiên runtime; đọc memory không fallback sang IDB.

Hook production không continue/step/debug-call target. Chỉ fixture driver trong `work/` tự Continue để chạy kiểm chứng memory-only program. Memory đọc live tối đa 64 KiB/field. Data/architecture ngoài adapter đã triển khai giữ unresolved.

## UI và export

Dùng native Choose/simplecustviewer/action, không cần Qt package bên ngoài. Chỉ action Append comment sửa comment; scan không rename function/patch instruction. Export chỉ ghi vào file người dùng chọn. Crypto draft không tự chọn padding/layout/counter/RSA defaults và luôn yêu cầu review; evidence giữ cả source/confidence/material status.

JSON trình bày dùng `to_dict(hex_addresses=True)`, full export dùng `ScanResult.dumps()`. Address-only conversion không đổi live model integer hoặc các scalar/lengths. Numeric `to_dict()` vẫn giữ tương thích với replay/test scripts cũ.

Thiết kế tập trung vào vị trí và dữ liệu có thể kiểm tra lại. Nó chưa giải tổng quát obfuscation, SIMD/vector propagation, dynamic private-key internals hay nhận diện mọi library/version. Các giới hạn sử dụng cụ thể nằm trong [README của project](../README.md).
