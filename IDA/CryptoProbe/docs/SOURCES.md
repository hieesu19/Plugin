# Nguồn tham khảo và provenance

Các nguồn chỉ cần lúc phát triển. Runtime không tải network, không yêu cầu service hoặc license ngoài IDA/Hex-Rays mà bạn đã có.

## Repository đã đọc

- [FindCrypt-YARA](https://github.com/polymorf/findcrypt-yara), commit `044644b9c52ae3e7b2305bac15b0c12c9e31a282`: tham khảo cách quét constant/rule và trình bày hit. Không copy rules/code GPL vào runtime BSD này. Project này không phân phối repository tham khảo hoặc bộ rules GPL đó.
- [HexRaysSA/IDAPython](https://github.com/HexRaysSA/IDAPython), commit `6885a0d0e4fe0d04366975f440a724819b08452e`: examples debugger hooks và native Choose. SDK Python của IDA 9.3 được đọc trực tiếp và kiểm tra bằng headless IDA.

## Tài liệu chính thức

- [IDAPython plugin framework](https://docs.hex-rays.com/8.5/developer-guide/idapython/how-to-create-a-plugin), [plugin_t API](https://python.docs.hex-rays.com/classida__idaapi_1_1plugin__t.html).
- [ida_hexrays API](https://python.docs.hex-rays.com/ida_hexrays/index.html), [ida_dbg API](https://python.docs.hex-rays.com/ida_dbg/index.html), [ida_idd API](https://python.docs.hex-rays.com/ida_idd/index.html): ctree, breakpoint/hooks, fresh debugger memory.
- [ida_funcs function/chunk API](https://python.docs.hex-rays.com/namespaceida__funcs.html), [idautils XrefsFrom/FuncItems](https://python.docs.hex-rays.com/namespaceidautils.html), [ida_xref code references](https://python.docs.hex-rays.com/namespaceida__xref.html): recursive function scope, tail jumps và không đi theo intra-function branches như callee mới; đã đối chiếu SDK local/native IDA 9.1.
- [OpenSSL EVP cipher initialization](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/), [OpenSSL ChaCha20 layout](https://docs.openssl.org/3.0/man3/EVP_chacha20/), [RSA padding setters](https://docs.openssl.org/3.0/man3/EVP_PKEY_CTX_set_rsa_padding/).
- [OpenSSL headers](https://github.com/openssl/openssl/tree/master/include/openssl): low-level AES/DES/RC4/RSA/BN prototypes.
- [Microsoft BCryptImportKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkey), [BCryptImportKeyPair](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptimportkeypair), [BCryptGenerateSymmetricKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey), [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt).
- [BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info), [BCRYPT_RSAKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob), [CryptoAPI key blobs](https://learn.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs).
- [mbedTLS header sources](https://github.com/Mbed-TLS/mbedtls/tree/v2.28.10/include/mbedtls): AES, DES, ARC4, ChaCha20, GCM profile families. API version có thể thay đổi; thêm/override profile nếu binary dùng prototype khác.
- [libsodium ChaCha20](https://doc.libsodium.org/advanced/stream_ciphers/chacha20), [Salsa20](https://doc.libsodium.org/advanced/stream_ciphers/salsa20), [ChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305), [libsodium public headers](https://github.com/jedisct1/libsodium/tree/master/src/libsodium/include/sodium).
- [Nettle AES documentation](https://www.lysator.liu.se/~nisse/nettle/nettle.html), [tiny-AES-c](https://github.com/kokke/tiny-AES-c): compile-time key size của tiny-AES không được tự mặc định.
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439), [NIST AES FIPS 197](https://csrc.nist.gov/pubs/fips/197/final), [NIST GCM SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final): layouts/algorithm constants.

Mỗi profile/heuristic vẫn có scope hữu hạn. Function name/signature/code feature có thể bị thay đổi hoặc giả; evidence và raw material status được giữ để người phân tích kiểm tra lại.
