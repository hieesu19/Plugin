# API profiles và phạm vi hỗ trợ

Tài liệu này mô tả cách Crypto Probe 1.3.0 đọc các API đã khai báo trong [builtin.json](../crypto_probe/rules/builtin.json): **109 profiles, 127 tên API**. Một profile có thể dùng chung cho nhiều aliases có cùng cách đọc arguments.

Đây là danh sách model đã triển khai trong plugin, không phải danh sách toàn bộ API của OpenSSL, Windows hay các thư viện khác. Tên function cần khớp sau bước chuẩn hóa; wrapper, API đổi tên hoặc prototype khác phiên bản có thể cần binding riêng.

## 1. Cách đọc bảng

- Argument indices bắt đầu từ **0**. `arg[3]` là tham số thứ tư.
- Length mặc định tính theo **byte**. `arg[1]/8` nghĩa là argument 1 chứa số bit, chia 8 để đổi thành byte.
- `ctx.key_length` hoặc `ctx.iv_length` là thuộc tính đã xác định từ cipher descriptor, setup call hoặc control operation trên cùng context.
- `opaque` chỉ là tham chiếu tới object; không tự dereference để tìm raw key.
- `unknown` nghĩa là bản thân profile chưa quy định thuật toán/mode. Decoder có thể bổ sung từ context. Ví dụ `EVP_EncryptInit_ex` dùng cùng prototype cho nhiều thuật toán.
- Cột scalar widths cho biết những arguments được khai báo độ rộng khác pointer width. Pointer/size_t không khai báo riêng dùng width của ABI.
- `—` ở return rule nghĩa là profile không khai báo `success`. Runtime có một số fallback theo API/event; khi không có predicate cụ thể, return metadata không xác nhận kết quả mã hóa đúng.

### Ví dụ OpenSSL EVP

```c
EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
```

Profile có 5 arguments. Key ở argument 3 và IV ở argument 4. Descriptor AES-256-CBC cung cấp key length 32 byte và IV length 16 byte. Nếu không xác định được descriptor/context, decoder có thể biết vị trí key pointer nhưng chưa đủ thông tin để đọc đúng buffer.

Cách dùng API: [OpenSSL EVP cipher initialization](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/). Cách khai báo profile riêng: [RULES.md](RULES.md).

## 2. Profile khác với kết quả capture

Bảng liệt kê fields đọc trực tiếp theo profile. Một số fields khác được tạo bởi decoder của event:

- BCrypt đọc output key handle sau return rồi nối với provider/key state đã theo dõi.
- RNG/KDF đọc output buffer sau return theo các chỉ số `random_output_arg`, `derived_output_arg` và length tương ứng.
- GCM/AEAD tag có xử lý riêng cho EVP GET_TAG, BCrypt auth info và libsodium combined-output encryption.
- RSA numbers có thể đến từ PEM/DER/blob parser hoặc các BN import/setup calls được theo dõi.

Data scan hiện tìm PEM rồi parse DER bên trong; không có bước dò mọi raw DER object theo từng offset trong database.

Nếu input đã quan sát nhưng API return thất bại, finding có thể vẫn giữ input đó; context/handle mới không được commit. Chi tiết ở [DESIGN.md](DESIGN.md#7-capture-khi-debug).

## 3. OpenSSL EVP cipher

EVP sử dụng cipher descriptor và context. Cần nối đúng init/control/update calls để xác định algorithm, mode và lengths. Các profiles `_ex2` chưa giải mã đầy đủ `OSSL_PARAM`; params khác NULL có thể làm length unresolved.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `EVP_EncryptInit` | 4 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[2] (ctx.key_length B)<br>`iv` ← arg[3] (ctx.iv_length B) | — | `openssl` |
| `EVP_EncryptInit_ex` | 5 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[3] (ctx.key_length B)<br>`iv` ← arg[4] (ctx.iv_length B) | — | `openssl` |
| `EVP_EncryptInit_ex2` | 5 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[2] (ctx.key_length B)<br>`iv` ← arg[3] (ctx.iv_length B) | — | `openssl` |
| `EVP_EncryptUpdate` | 5 | unknown / unknown | `context_use` / arg[0] | `input` ← arg[3] (arg[4] B) | arg[4]=4 B | `openssl` |
| `EVP_EncryptFinal`, `EVP_EncryptFinal_ex` | 3 | unknown / unknown | `context_use` / arg[0] | — | — | `openssl` |
| `EVP_DecryptInit` | 4 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[2] (ctx.key_length B)<br>`iv` ← arg[3] (ctx.iv_length B) | — | `openssl` |
| `EVP_DecryptInit_ex` | 5 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[3] (ctx.key_length B)<br>`iv` ← arg[4] (ctx.iv_length B) | — | `openssl` |
| `EVP_DecryptInit_ex2` | 5 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[2] (ctx.key_length B)<br>`iv` ← arg[3] (ctx.iv_length B) | — | `openssl` |
| `EVP_DecryptUpdate` | 5 | unknown / unknown | `context_use` / arg[0] | `input` ← arg[3] (arg[4] B) | arg[4]=4 B | `openssl` |
| `EVP_DecryptFinal`, `EVP_DecryptFinal_ex` | 3 | unknown / unknown | `context_use` / arg[0] | — | — | `openssl` |
| `EVP_CipherInit` | 5 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[2] (ctx.key_length B)<br>`iv` ← arg[3] (ctx.iv_length B) | arg[4]=4 B | `openssl` |
| `EVP_CipherInit_ex` | 6 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[3] (ctx.key_length B)<br>`iv` ← arg[4] (ctx.iv_length B) | arg[5]=4 B | `openssl` |
| `EVP_CipherInit_ex2` | 6 | unknown / unknown | `evp_init` / arg[0] | `key` ← arg[2] (ctx.key_length B)<br>`iv` ← arg[3] (ctx.iv_length B) | arg[4]=4 B | `openssl` |
| `EVP_CipherUpdate` | 5 | unknown / unknown | `context_use` / arg[0] | `input` ← arg[3] (arg[4] B) | arg[4]=4 B | `openssl` |
| `EVP_CipherFinal`, `EVP_CipherFinal_ex` | 3 | unknown / unknown | `context_use` / arg[0] | — | — | `openssl` |
| `EVP_CIPHER_CTX_ctrl` | 4 | unknown / unknown | `evp_ctrl` / arg[0] | `control` ← arg[1] (scalar)<br>`control_value` ← arg[2] (scalar) | arg[1]=4 B, arg[2]=4 B | `openssl` |
| `EVP_CIPHER_CTX_set_padding` | 2 | unknown / unknown | `set_padding` / arg[0] | `padding_enabled` ← arg[1] (scalar) | arg[1]=4 B | `openssl` |
| `EVP_CIPHER_CTX_set_key_length` | 2 | unknown / unknown | `set_key_length` / arg[0] | `key_length` ← arg[1] (scalar) | arg[1]=4 B | `openssl` |
| `EVP_CIPHER_fetch` | 3 | unknown / unknown | `cipher_fetch` | `cipher_name` ← arg[1] (cstring) | — | `pointer` |
| `EVP_get_cipherbyname` | 1 | unknown / unknown | `cipher_fetch` | `cipher_name` ← arg[0] (cstring) | — | `pointer` |

## 4. OpenSSL AES, DES và RC4

Các set-key APIs nhận raw key rồi tạo schedule/state. Decoder nối các lần dùng cùng context; không coi bytes của expanded schedule hoặc RC4 state là raw key.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `AES_set_encrypt_key`, `AES_set_decrypt_key` | 3 | AES / unknown | `setkey` / arg[2] | `key` ← arg[0] (arg[1]/8 B)<br>`key_bits` ← arg[1] (scalar) | arg[1]=4 B | `zero` |
| `AES_cbc_encrypt` | 6 | AES / CBC | `context_use` / arg[3] | `iv` ← arg[4] (16 B)<br>`input` ← arg[0] (arg[2] B) | arg[5]=4 B | `void` |
| `AES_ecb_encrypt` | 4 | AES / ECB | `context_use` / arg[2] | `input` ← arg[0] (16 B) | arg[3]=4 B | `void` |
| `AES_cfb128_encrypt` | 7 | AES / CFB | `context_use` / arg[3] | `iv` ← arg[4] (16 B) | arg[6]=4 B | `void` |
| `AES_cfb8_encrypt` | 7 | AES / CFB | `context_use` / arg[3] | `iv` ← arg[4] (16 B) | arg[6]=4 B | `void` |
| `AES_ofb128_encrypt` | 6 | AES / OFB | `context_use` / arg[3] | `iv` ← arg[4] (16 B) | — | `void` |
| `AES_ctr128_encrypt` | 7 | AES / CTR | `context_use` / arg[3] | `counter_block` ← arg[4] (16 B) | — | `void` |
| `CRYPTO_ctr128_encrypt` | 8 | unknown / CTR | `context_use` / arg[3] | `counter_block` ← arg[4] (16 B) | — | — |
| `RC4_set_key` | 3 | RC4 / STREAM | `setkey` / arg[0] | `key` ← arg[2] (arg[1] B) | arg[1]=4 B | `void` |
| `RC4` | 4 | RC4 / STREAM | `context_use` / arg[0] | `input` ← arg[2] (arg[1] B) | — | `void` |
| `DES_set_key`, `DES_set_key_checked` | 2 | DES / unknown | `setkey` / arg[1] | `key` ← arg[0] (8 B) | — | `zero` |
| `DES_set_key_unchecked` | 2 | DES / unknown | `setkey` / arg[1] | `key` ← arg[0] (8 B) | — | `void` |
| `DES_ecb_encrypt` | 4 | DES / ECB | `context_use` / arg[2] | `input` ← arg[0] (8 B) | arg[3]=4 B | `void` |
| `DES_cbc_encrypt`, `DES_ncbc_encrypt` | 6 | DES / CBC | `context_use` / arg[3] | `iv` ← arg[4] (8 B) | arg[2]=c_long, arg[5]=4 B | `void` |
| `DES_cfb64_encrypt` | 7 | DES / CFB | `context_use` / arg[3] | `iv` ← arg[4] (8 B) | arg[2]=c_long, arg[6]=4 B | `void` |
| `DES_ofb64_encrypt` | 6 | DES / OFB | `context_use` / arg[3] | `iv` ← arg[4] (8 B) | arg[2]=c_long | `void` |
| `DES_cfb_encrypt` | 7 | DES / CFB | `context_use` / arg[4] | `iv` ← arg[5] (8 B)<br>`cfb_segment_bits` ← arg[2] (scalar) | arg[2]=4 B, arg[3]=c_long, arg[6]=4 B | `void` |
| `DES_ofb_encrypt` | 6 | DES / OFB | `context_use` / arg[4] | `iv` ← arg[5] (8 B)<br>`segment_bits` ← arg[2] (scalar) | arg[2]=4 B, arg[3]=c_long | `void` |

## 5. mbedTLS

Các profiles tham chiếu nhóm API trong mbedTLS 2.x. GCM dùng chung interface cho cipher IDs; algorithm có thể còn unknown nếu chưa xác định được cipher_id/context.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `mbedtls_aes_setkey_enc` | 3 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (arg[2]/8 B)<br>`key_bits` ← arg[2] (scalar) | arg[2]=4 B | `mbedtls` |
| `mbedtls_aes_setkey_dec` | 3 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (arg[2]/8 B)<br>`key_bits` ← arg[2] (scalar) | arg[2]=4 B | `mbedtls` |
| `mbedtls_aes_crypt_ecb` | 4 | AES / ECB | `context_use` / arg[0] | `input` ← arg[2] (16 B) | arg[1]=4 B | `mbedtls` |
| `mbedtls_aes_crypt_cbc` | 6 | AES / CBC | `context_use` / arg[0] | `iv` ← arg[3] (16 B) | arg[1]=4 B | `mbedtls` |
| `mbedtls_aes_crypt_ctr` | 7 | AES / CTR | `context_use` / arg[0] | `counter_block` ← arg[3] (16 B)<br>`stream_block` ← arg[4] (16 B) | — | `mbedtls` |
| `mbedtls_aes_crypt_cfb128` | 7 | AES / CFB | `context_use` / arg[0] | `iv` ← arg[4] (16 B) | arg[1]=4 B | `mbedtls` |
| `mbedtls_aes_crypt_cfb8` | 6 | AES / CFB | `context_use` / arg[0] | `iv` ← arg[3] (16 B) | arg[1]=4 B | `mbedtls` |
| `mbedtls_aes_crypt_ofb` | 6 | AES / OFB | `context_use` / arg[0] | `iv` ← arg[3] (16 B) | — | `mbedtls` |
| `mbedtls_des_setkey_enc`, `mbedtls_des_setkey_dec` | 2 | DES / unknown | `setkey` / arg[0] | `key` ← arg[1] (8 B) | — | `mbedtls` |
| `mbedtls_des_crypt_ecb` | 3 | DES / ECB | `context_use` / arg[0] | — | — | `mbedtls` |
| `mbedtls_des_crypt_cbc` | 6 | DES / CBC | `context_use` / arg[0] | `iv` ← arg[3] (8 B) | arg[1]=4 B | `mbedtls` |
| `mbedtls_arc4_setup` | 3 | RC4 / STREAM | `setkey` / arg[0] | `key` ← arg[1] (arg[2] B) | — | `void` |
| `mbedtls_arc4_crypt` | 4 | RC4 / STREAM | `context_use` / arg[0] | — | — | `mbedtls` |
| `mbedtls_chacha20_setkey` | 2 | ChaCha20 / STREAM | `setkey` / arg[0] | `key` ← arg[1] (32 B) | — | `mbedtls` |
| `mbedtls_chacha20_starts` | 3 | ChaCha20 / STREAM | `context_use` / arg[0] | `nonce` ← arg[1] (12 B)<br>`counter` ← arg[2] (scalar) | arg[2]=4 B | `mbedtls` |
| `mbedtls_chacha20_update` | 4 | ChaCha20 / STREAM | `context_use` / arg[0] | — | — | `mbedtls` |
| `mbedtls_chacha20_crypt` | 6 | ChaCha20 / STREAM | `direct` | `key` ← arg[0] (32 B)<br>`nonce` ← arg[1] (12 B)<br>`counter` ← arg[2] (scalar)<br>`input` ← arg[4] (arg[3] B) | arg[2]=4 B | `mbedtls` |
| `mbedtls_gcm_setkey` | 4 | unknown / GCM | `setkey` / arg[0] | `key` ← arg[2] (arg[3]/8 B)<br>`cipher_id` ← arg[1] (scalar) | arg[1]=4 B, arg[3]=4 B | `mbedtls` |
| `mbedtls_gcm_crypt_and_tag` | 11 | unknown / GCM | `context_use` / arg[0] | `nonce` ← arg[3] (arg[4] B)<br>`aad` ← arg[5] (arg[6] B)<br>`tag` ← arg[10] (arg[9] B) | arg[1]=4 B | `mbedtls` |
| `mbedtls_gcm_auth_decrypt` | 10 | unknown / GCM | `context_use` / arg[0] | `nonce` ← arg[2] (arg[3] B)<br>`aad` ← arg[4] (arg[5] B)<br>`tag` ← arg[6] (arg[7] B) | — | `mbedtls` |

## 6. libsodium

Các biến thể được phân biệt bằng API: ChaCha20 original có nonce 8 byte, IETF có nonce 12 byte, XChaCha20 có nonce 24 byte. Tag của combined-output encryption được đọc riêng sau return khi lấy được output length.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `crypto_stream_salsa20_xor` | 5 | Salsa20 / STREAM | `direct` | `key` ← arg[4] (32 B)<br>`nonce` ← arg[3] (8 B) | arg[2]=8 B | `zero` |
| `crypto_stream_salsa20_xor_ic` | 6 | Salsa20 / STREAM | `direct` | `key` ← arg[5] (32 B)<br>`nonce` ← arg[3] (8 B)<br>`counter` ← arg[4] (scalar) | arg[2]=8 B, arg[4]=8 B | `zero` |
| `crypto_stream_salsa20` | 4 | Salsa20 / STREAM | `direct` | `key` ← arg[3] (32 B)<br>`nonce` ← arg[2] (8 B) | arg[1]=8 B | `zero` |
| `crypto_stream_chacha20_xor` | 5 | ChaCha20 / STREAM | `direct` | `key` ← arg[4] (32 B)<br>`nonce` ← arg[3] (8 B) | arg[2]=8 B | `zero` |
| `crypto_stream_chacha20_xor_ic` | 6 | ChaCha20 / STREAM | `direct` | `key` ← arg[5] (32 B)<br>`nonce` ← arg[3] (8 B)<br>`counter` ← arg[4] (scalar) | arg[2]=8 B, arg[4]=8 B | `zero` |
| `crypto_stream_chacha20` | 4 | ChaCha20 / STREAM | `direct` | `key` ← arg[3] (32 B)<br>`nonce` ← arg[2] (8 B) | arg[1]=8 B | `zero` |
| `crypto_stream_chacha20_ietf_xor` | 5 | ChaCha20 / STREAM | `direct` | `key` ← arg[4] (32 B)<br>`nonce` ← arg[3] (12 B) | arg[2]=8 B | `zero` |
| `crypto_stream_chacha20_ietf_xor_ic` | 6 | ChaCha20 / STREAM | `direct` | `key` ← arg[5] (32 B)<br>`nonce` ← arg[3] (12 B)<br>`counter` ← arg[4] (scalar) | arg[2]=8 B, arg[4]=4 B | `zero` |
| `crypto_stream_chacha20_ietf` | 4 | ChaCha20 / STREAM | `direct` | `key` ← arg[3] (32 B)<br>`nonce` ← arg[2] (12 B) | arg[1]=8 B | `zero` |
| `crypto_stream_xchacha20_xor` | 5 | XChaCha20 / STREAM | `direct` | `key` ← arg[4] (32 B)<br>`nonce` ← arg[3] (24 B) | arg[2]=8 B | `zero` |
| `crypto_stream_xchacha20_xor_ic` | 6 | XChaCha20 / STREAM | `direct` | `key` ← arg[5] (32 B)<br>`nonce` ← arg[3] (24 B)<br>`counter` ← arg[4] (scalar) | arg[2]=8 B, arg[4]=8 B | `zero` |
| `crypto_stream_xchacha20` | 4 | XChaCha20 / STREAM | `direct` | `key` ← arg[3] (32 B)<br>`nonce` ← arg[2] (24 B) | arg[1]=8 B | `zero` |
| `crypto_aead_chacha20poly1305_ietf_encrypt` | 9 | ChaCha20-Poly1305 / AEAD | `direct` | `key` ← arg[8] (32 B)<br>`nonce` ← arg[7] (12 B)<br>`aad` ← arg[4] (arg[5] B) | arg[3]=8 B, arg[5]=8 B | `zero` |
| `crypto_aead_chacha20poly1305_ietf_decrypt` | 9 | ChaCha20-Poly1305 / AEAD | `direct` | `key` ← arg[8] (32 B)<br>`nonce` ← arg[7] (12 B)<br>`aad` ← arg[5] (arg[6] B) | arg[4]=8 B, arg[6]=8 B | `zero` |
| `crypto_aead_xchacha20poly1305_ietf_encrypt` | 9 | XChaCha20-Poly1305 / AEAD | `direct` | `key` ← arg[8] (32 B)<br>`nonce` ← arg[7] (24 B)<br>`aad` ← arg[4] (arg[5] B) | arg[3]=8 B, arg[5]=8 B | `zero` |
| `crypto_aead_xchacha20poly1305_ietf_decrypt` | 9 | XChaCha20-Poly1305 / AEAD | `direct` | `key` ← arg[8] (32 B)<br>`nonce` ← arg[7] (24 B)<br>`aad` ← arg[5] (arg[6] B) | arg[4]=8 B, arg[6]=8 B | `zero` |
| `crypto_aead_aes256gcm_encrypt` | 9 | AES / GCM | `direct` | `key` ← arg[8] (32 B)<br>`nonce` ← arg[7] (12 B)<br>`aad` ← arg[4] (arg[5] B) | arg[3]=8 B, arg[5]=8 B | `zero` |
| `crypto_aead_aes256gcm_decrypt` | 9 | AES / GCM | `direct` | `key` ← arg[8] (32 B)<br>`nonce` ← arg[7] (12 B)<br>`aad` ← arg[5] (arg[6] B) | arg[4]=8 B, arg[6]=8 B | `zero` |

## 7. Nettle và tiny-AES

Nettle profiles hiện mô tả bước setup key. tiny-AES có key size phụ thuộc compile-time; không mặc định AES-128 nếu chưa có key_length đáng tin cậy.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `nettle_aes128_set_encrypt_key`, `nettle_aes128_set_decrypt_key` | 2 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (16 B) | — | `void` |
| `nettle_aes192_set_encrypt_key`, `nettle_aes192_set_decrypt_key` | 2 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (24 B) | — | `void` |
| `nettle_aes256_set_encrypt_key`, `nettle_aes256_set_decrypt_key` | 2 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (32 B) | — | `void` |
| `AES_init_ctx` | 2 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (ctx.key_length B) | — | `void` |
| `AES_init_ctx_iv` | 3 | AES / unknown | `setkey` / arg[0] | `key` ← arg[1] (ctx.key_length B)<br>`iv` ← arg[2] (16 B) | — | `void` |
| `AES_CBC_encrypt_buffer`, `AES_CBC_decrypt_buffer` | 3 | AES / CBC | `context_use` / arg[0] | — | — | `void` |
| `AES_ECB_encrypt`, `AES_ECB_decrypt` | 2 | AES / ECB | `context_use` / arg[0] | — | — | `void` |
| `AES_CTR_xcrypt_buffer` | 3 | AES / CTR | `context_use` / arg[0] | — | — | `void` |

## 8. RSA và BIGNUM

RSA*/EVP_PKEY*/BIGNUM* là opaque objects. Chỉ đọc số lớn khi theo được import/setup hoặc parse định dạng đã hỗ trợ. Các EVP_PKEY APIs có thể phục vụ nhiều loại khóa; không kết luận RSA từ tên generic API này.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `RSA_public_encrypt`, `RSA_private_encrypt`, `RSA_public_decrypt`, `RSA_private_decrypt` | 5 | RSA / unknown | `rsa_use` / arg[3] | `rsa_handle` ← arg[3] (opaque)<br>`rsa_padding` ← arg[4] (scalar) | arg[0]=4 B, arg[4]=4 B | `positive32` |
| `RSA_set0_key` | 4 | RSA / unknown | `rsa_setkey` / arg[0] | `n` ← arg[1] (opaque)<br>`e` ← arg[2] (opaque)<br>`d` ← arg[3] (opaque) | — | — |
| `BN_bin2bn` | 3 | unknown / unknown | `bignum_import` | `bignum_bytes` ← arg[0] (arg[1] B) | — | `pointer` |
| `BN_set_word` | 2 | unknown / unknown | `bignum_word` / arg[0] | `word` ← arg[1] (scalar) | — | `bool` |
| `EVP_PKEY_CTX_set_rsa_padding` | 2 | RSA / unknown | `rsa_padding` / arg[0] | `rsa_padding` ← arg[1] (scalar) | arg[1]=4 B | `openssl` |
| `EVP_PKEY_CTX_set_rsa_oaep_md`, `EVP_PKEY_CTX_set_rsa_mgf1_md` | 2 | RSA / unknown | `rsa_hash` / arg[0] | — | — | `openssl` |
| `EVP_PKEY_CTX_set0_rsa_oaep_label` | 3 | RSA / unknown | `context_use` / arg[0] | `oaep_label` ← arg[1] (arg[2] B) | — | `openssl` |
| `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt` | 5 | unknown / unknown | `context_use` / arg[0] | — | — | `openssl` |

## 9. Windows BCrypt / CNG

Phân biệt algorithm provider handle và key handle. Raw key đi vào BCryptGenerateSymmetricKey qua pbSecret; phKey là output pointer chứa handle sau return. Mode có thể được cấu hình bằng BCryptSetProperty.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `BCryptOpenAlgorithmProvider` | 4 | unknown / unknown | `cng_open` | `algorithm_name` ← arg[1] (utf16)<br>`handle_out` ← arg[0] (pointer) | arg[3]=4 B | `ntstatus` |
| `BCryptSetProperty` | 5 | unknown / unknown | `cng_property` / arg[0] | `property_name` ← arg[1] (utf16)<br>`property_data` ← arg[2] (arg[3] B) | arg[3]=4 B, arg[4]=4 B | `ntstatus` |
| `BCryptGenerateSymmetricKey` | 7 | unknown / unknown | `cng_key` / arg[0] | `key` ← arg[4] (arg[5] B) | arg[3]=4 B, arg[5]=4 B, arg[6]=4 B | `ntstatus` |
| `BCryptImportKey` | 9 | unknown / unknown | `cng_import` / arg[0] | `blob_type` ← arg[2] (utf16)<br>`key_blob` ← arg[6] (arg[7] B) | arg[5]=4 B, arg[7]=4 B, arg[8]=4 B | `ntstatus` |
| `BCryptImportKeyPair` | 7 | unknown / unknown | `cng_import` / arg[0] | `blob_type` ← arg[2] (utf16)<br>`key_blob` ← arg[4] (arg[5] B) | arg[5]=4 B, arg[6]=4 B | `ntstatus` |
| `BCryptEncrypt`, `BCryptDecrypt` | 10 | unknown / unknown | `cng_use` / arg[0] | `iv` ← arg[4] (arg[5] B)<br>`padding_info` ← arg[3] (pointer)<br>`flags` ← arg[9] (scalar) | arg[2]=4 B, arg[5]=4 B, arg[7]=4 B, arg[9]=4 B | `ntstatus` |
| `BCryptDestroyKey` | 1 | unknown / unknown | `destroy_context` / arg[0] | — | — | `ntstatus` |
| `BCryptCloseAlgorithmProvider` | 2 | unknown / unknown | `destroy_context` / arg[0] | — | arg[1]=4 B | `ntstatus` |

## 10. Windows CryptoAPI

CryptImportKey có thể cung cấp key blob; CryptSetKeyParam cấu hình thêm mode/IV theo parameter. CryptEncrypt/CryptDecrypt nhận key handle, không nhận raw key trực tiếp.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `CryptImportKey` | 6 | unknown / unknown | `capi_import` / arg[0] | `key_blob` ← arg[1] (arg[2] B) | arg[2]=4 B, arg[4]=4 B | `bool` |
| `CryptSetKeyParam` | 4 | unknown / unknown | `capi_property` / arg[0] | `parameter` ← arg[1] (scalar)<br>`parameter_pointer` ← arg[2] (pointer) | arg[1]=4 B, arg[3]=4 B | `bool` |
| `CryptEncrypt` | 7 | unknown / unknown | `capi_use` / arg[0] | `final` ← arg[2] (scalar) | arg[2]=4 B, arg[3]=4 B, arg[6]=4 B | `bool` |
| `CryptDecrypt` | 6 | unknown / unknown | `capi_use` / arg[0] | `final` ← arg[2] (scalar) | arg[2]=4 B, arg[3]=4 B | `bool` |
| `CryptDestroyKey` | 1 | unknown / unknown | `destroy_context` / arg[0] | — | — | `bool` |

## 11. RNG và KDF

Output chỉ có sau return. Buffer ngẫu nhiên hoặc derived buffer chưa tự chứng minh sẽ được dùng làm key; cần theo dõi nơi sử dụng tiếp theo.

| API / aliases | argc | Algorithm / mode | Event / context | Fields | Scalar widths | Return rule |
|---|---:|---|---|---|---|---|
| `PKCS5_PBKDF2_HMAC` | 8 | unknown / unknown | `kdf` | `password` ← arg[0] (arg[1] B)<br>`salt` ← arg[2] (arg[3] B)<br>`iterations` ← arg[4] (scalar)<br>`derived_key_length` ← arg[6] (scalar) | arg[1]=4 B, arg[3]=4 B, arg[4]=4 B, arg[6]=4 B | `openssl` |
| `getrandom` | 3 | unknown / unknown | `random` | `random_output` ← arg[0] (pointer) | arg[2]=4 B | `positive` |
| `RAND_bytes` | 2 | unknown / unknown | `random` | `random_output` ← arg[0] (pointer) | arg[1]=4 B | `openssl` |
| `BCryptGenRandom` | 4 | unknown / unknown | `random` | `random_output` ← arg[1] (pointer) | arg[2]=4 B, arg[3]=4 B | `ntstatus` |

## 12. Cipher descriptors không nằm trong profile table

`apis.cipher_descriptor()` xử lý riêng các getter sau để đưa mô tả thuật toán vào bước EVP init:

| Getter | Thông tin được tạo |
|---|---|
| `EVP_aes_{128,192,256}_{ecb,cbc,ctr,cfb128,cfb8,cfb1,ofb,gcm}` | AES, key size và mode; CFB segment bits khi có |
| `EVP_des_{ecb,cbc,cfb64,cfb8,cfb1,ofb}` | DES, mode và CFB segment bits |
| `EVP_rc4`, `EVP_rc4_40` | RC4, key length mặc định theo getter |
| `EVP_chacha20` | Key 32 byte, IV 16 byte: LE64 counter + nonce 8 byte theo interface OpenSSL |
| `EVP_chacha20_poly1305` | Key 32 byte, nonce 12 byte |

Các độ dài do descriptor cung cấp là mặc định của interface được mô hình hóa. Control/set-key-length calls có thể thay đổi thuộc tính context. Một pointer tới descriptor chưa biết không được cast để đoán layout nội bộ.

`EVP_CIPHER_fetch` và `EVP_get_cipherbyname` được xử lý bằng tên cipher. Tên CFB không ghi segment được map sang CFB128 cho AES, CFB64 cho DES. Với OpenSSL ChaCha20 cần phân biệt IV 16 byte của API với nonce 8 byte nằm bên trong nó. Tham chiếu: [OpenSSL ChaCha20](https://docs.openssl.org/3.0/man3/EVP_chacha20/).

## 13. Return predicates

| Rule | Điều kiện plugin áp dụng |
|---|---|
| `void` | Không kiểm tra return code |
| `bool` | 32 bit thấp khác 0 |
| `openssl` | 32 bit thấp bằng 1 |
| `zero`, `mbedtls`, `ntstatus` | 32 bit thấp bằng 0 |
| `pointer` | Khác 0 |
| `positive` | Giá trị signed dương theo xử lý width của runtime |
| `positive32` | Signed int32 dương |

Các predicates này phục vụ state tracking. Chúng không kiểm tra ciphertext hay authentication bằng một implementation độc lập. `ntstatus` hiện kiểm tra bằng 0, không triển khai toàn bộ macro NT_SUCCESS cho mọi status code.

## 14. Những phần cần xác định riêng

- Mode của code tự cài đặt chỉ có AES instruction/S-box hoặc TEA delta.
- Variant/round count/state layout của ChaCha/Salsa-family candidates.
- Raw key từ expanded key schedule hay opaque object khi thiếu bước setup/import.
- Padding, original size, file header/trailer, filename extension và input/output paths.
- Counter packing/endian nếu API hoặc code chưa cung cấp đủ thông tin.
- OAEP hash, MGF1 hash và label khi chỉ có PEM/DER key.
- API/provider/version ngoài các profiles đã nêu hoặc prototype bị Hex-Rays khôi phục sai.

Thêm binding hoặc override profile theo [RULES.md](RULES.md). Khi đổi lengths/ABI hoặc event xử lý context, cần đối chiếu cả input và return phase; chỉ sửa tên algorithm không bổ sung được cách đọc dữ liệu.
