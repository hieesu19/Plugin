# Tài liệu tham chiếu

Các tài liệu dưới đây được dùng để đối chiếu API, calling convention, định dạng khóa và các dấu hiệu nhận diện. Chúng mô tả giao diện bên ngoài; phần plugin đã triển khai cụ thể nằm trong [API_COVERAGE.md](API_COVERAGE.md) và `crypto_probe/rules/builtin.json`.

## IDA và IDAPython

| Tài liệu | Phần liên quan trong plugin |
|---|---|
| [IDAPython plugin framework — IDA 9.1](https://docs.hex-rays.com/9.1/developer-guide/idapython/how-to-create-a-plugin) | `plugin_t`, `plugmod_t`, entry point và vòng đời plugin |
| [ida_hexrays](https://python.docs.hex-rays.com/ida_hexrays/index.html) | Ctree, biểu thức/câu lệnh và các kiểu dùng trong bước tạo IR |
| [ida_funcs](https://python.docs.hex-rays.com/namespaceida__funcs.html), [idautils](https://python.docs.hex-rays.com/namespaceidautils.html), [ida_xref](https://python.docs.hex-rays.com/namespaceida__xref.html) | Functions, code references, call graph và tail-call discovery |
| [ida_dbg](https://python.docs.hex-rays.com/ida_dbg/index.html), [ida_idd](https://python.docs.hex-rays.com/ida_idd/index.html) | Debugger events, breakpoints và đọc memory của process |
| [HexRaysSA/IDAPython](https://github.com/HexRaysSA/IDAPython) | Mã nguồn/examples về UI và debugger hooks |

Tài liệu IDAPython trực tuyến có thể theo SDK mới hơn IDA đang cài. Khi gặp khác biệt tên hàm hoặc kiểu dữ liệu, cần đối chiếu SDK đi kèm đúng phiên bản IDA.

## API mã hóa

### OpenSSL

- [EVP_EncryptInit và các hàm EVP cipher](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/): cipher descriptor, context, key/IV, update/final và control operations.
- [EVP_chacha20](https://docs.openssl.org/3.0/man3/EVP_chacha20/): phân biệt layout IV của OpenSSL ChaCha20 với nonce của ChaCha20-Poly1305.
- [EVP_PKEY_CTX control operations](https://docs.openssl.org/3.0/man3/EVP_PKEY_CTX_ctrl/): RSA padding, OAEP hash, MGF1 hash và label.
- [OpenSSL public headers](https://github.com/openssl/openssl/tree/master/include/openssl): đối chiếu prototypes AES/DES/RC4/RSA/BN. Nhánh master có thể khác phiên bản thư viện trong binary.

### Windows CNG và CryptoAPI

- [BCryptGenerateSymmetricKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey): raw secret input, output key handle và độ rộng ULONG.
- [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt): key handle, IV, flags, padding info và output parameters.
- [BCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkey), [BCryptImportKeyPair](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair): import key blobs.
- [BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info): nonce, AAD và authentication tag.
- [BCRYPT_RSAKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob), [CryptoAPI key blobs](https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs): các layouts và thành phần khóa có thể parse.

### Các thư viện khác

- [mbedTLS 2.28.10 headers](https://github.com/Mbed-TLS/mbedtls/tree/v2.28.10/include/mbedtls): AES, DES, ARC4, ChaCha20 và GCM prototypes. API ở phiên bản khác cần được kiểm tra riêng.
- libsodium: [ChaCha20](https://doc.libsodium.org/advanced/stream_ciphers/chacha20), [Salsa20](https://doc.libsodium.org/advanced/stream_ciphers/salsa20), [ChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305), [public headers](https://github.com/jedisct1/libsodium/tree/master/src/libsodium/include/sodium). Dùng để đối chiếu nonce length, counter và combined ciphertext/tag output.
- [Nettle](https://www.lysator.liu.se/~nisse/nettle/nettle.html): AES key-setup interfaces.
- [tiny-AES-c](https://github.com/kokke/tiny-AES-c): ctx/IV interfaces; key length còn phụ thuộc cấu hình compile-time.

## ABI và định dạng thuật toán

- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention): register arguments, shadow space và arguments trên stack. Phần áp dụng trong plugin được giải thích tại [DESIGN.md](DESIGN.md#7-capture-khi-debug).
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439): ChaCha20, Poly1305 và IETF AEAD layout.
- [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final): AES, S-box và các tham số thuật toán.
- [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final): GCM và authentication tag.

Một profile ABI không có nghĩa đã bao phủ mọi cách truyền floating-point, vector hoặc aggregate arguments của platform đó. Tương tự, pattern round function chưa chứng minh toàn bộ implementation tuân theo chuẩn thuật toán.

## Công cụ tham khảo

[FindCrypt-YARA](https://github.com/polymorf/findcrypt-yara) được tham khảo về cách tìm constant fingerprints và hiển thị vị trí hit. Project này không đóng gói repository hoặc bộ rules GPL của FindCrypt-YARA. Fingerprints trong `signatures.py` được khai báo/tạo trực tiếp, gồm AES S-box, DES tables và sigma/tau.

Runtime Crypto Probe không tải các nguồn trên khi quét. Các link dùng để tra cứu và kiểm tra lại implementation.
