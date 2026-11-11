# API coverage — profiles đã triển khai

Argument indices bắt đầu từ 0. Fixed length là byte; length_from phụ thuộc context evidence. Tên API đủ để chọn prototype, không tự chứng minh raw key đã đọc được. Scalar widths nằm trong builtin.json.

| API name / aliases | argc | Algorithm / mode | Event / context | Material roles | Return contract |
|---|---:|---|---|---|---|
| `EVP_EncryptInit` | 4 | unknown / unknown | evp_init / ctx@0 | key@2 (key_length); iv@3 (iv_length) | openssl |
| `EVP_EncryptInit_ex` | 5 | unknown / unknown | evp_init / ctx@0 | key@3 (key_length); iv@4 (iv_length) | openssl |
| `EVP_EncryptInit_ex2` | 5 | unknown / unknown | evp_init / ctx@0 | key@2 (key_length); iv@3 (iv_length) | openssl |
| `EVP_EncryptUpdate` | 5 | unknown / unknown | context_use / ctx@0 | input@3 (arg4) | openssl |
| `EVP_EncryptFinal`, `EVP_EncryptFinal_ex` | 3 | unknown / unknown | context_use / ctx@0 |  | openssl |
| `EVP_DecryptInit` | 4 | unknown / unknown | evp_init / ctx@0 | key@2 (key_length); iv@3 (iv_length) | openssl |
| `EVP_DecryptInit_ex` | 5 | unknown / unknown | evp_init / ctx@0 | key@3 (key_length); iv@4 (iv_length) | openssl |
| `EVP_DecryptInit_ex2` | 5 | unknown / unknown | evp_init / ctx@0 | key@2 (key_length); iv@3 (iv_length) | openssl |
| `EVP_DecryptUpdate` | 5 | unknown / unknown | context_use / ctx@0 | input@3 (arg4) | openssl |
| `EVP_DecryptFinal`, `EVP_DecryptFinal_ex` | 3 | unknown / unknown | context_use / ctx@0 |  | openssl |
| `EVP_CipherInit` | 5 | unknown / unknown | evp_init / ctx@0 | key@2 (key_length); iv@3 (iv_length) | openssl |
| `EVP_CipherInit_ex` | 6 | unknown / unknown | evp_init / ctx@0 | key@3 (key_length); iv@4 (iv_length) | openssl |
| `EVP_CipherInit_ex2` | 6 | unknown / unknown | evp_init / ctx@0 | key@2 (key_length); iv@3 (iv_length) | openssl |
| `EVP_CipherUpdate` | 5 | unknown / unknown | context_use / ctx@0 | input@3 (arg4) | openssl |
| `EVP_CipherFinal`, `EVP_CipherFinal_ex` | 3 | unknown / unknown | context_use / ctx@0 |  | openssl |
| `EVP_CIPHER_CTX_ctrl` | 4 | unknown / unknown | evp_ctrl / ctx@0 | control@1 (scalar); control_value@2 (scalar) | openssl |
| `EVP_CIPHER_CTX_set_padding` | 2 | unknown / unknown | set_padding / ctx@0 | padding_enabled@1 (scalar) | openssl |
| `EVP_CIPHER_CTX_set_key_length` | 2 | unknown / unknown | set_key_length / ctx@0 | key_length@1 (scalar) | openssl |
| `EVP_CIPHER_fetch` | 3 | unknown / unknown | cipher_fetch | cipher_name@1 (cstring) | pointer |
| `EVP_get_cipherbyname` | 1 | unknown / unknown | cipher_fetch | cipher_name@0 (cstring) | pointer |
| `AES_set_encrypt_key`, `AES_set_decrypt_key` | 3 | AES / unknown | setkey / ctx@2 | key@0 (arg1/8); key_bits@1 (scalar) | zero |
| `AES_cbc_encrypt` | 6 | AES / CBC | context_use / ctx@3 | iv@4 (16B); input@0 (arg2) | void |
| `AES_ecb_encrypt` | 4 | AES / ECB | context_use / ctx@2 | input@0 (16B) | void |
| `AES_cfb128_encrypt` | 7 | AES / CFB | context_use / ctx@3 | iv@4 (16B) | void |
| `AES_cfb8_encrypt` | 7 | AES / CFB | context_use / ctx@3 | iv@4 (16B) | void |
| `AES_ofb128_encrypt` | 6 | AES / OFB | context_use / ctx@3 | iv@4 (16B) | void |
| `AES_ctr128_encrypt` | 7 | AES / CTR | context_use / ctx@3 | counter_block@4 (16B) | void |
| `CRYPTO_ctr128_encrypt` | 8 | unknown / CTR | context_use / ctx@3 | counter_block@4 (16B) | unspecified |
| `RC4_set_key` | 3 | RC4 / STREAM | setkey / ctx@0 | key@2 (arg1) | void |
| `RC4` | 4 | RC4 / STREAM | context_use / ctx@0 | input@2 (arg1) | void |
| `DES_set_key`, `DES_set_key_checked` | 2 | DES / unknown | setkey / ctx@1 | key@0 (8B) | zero |
| `DES_set_key_unchecked` | 2 | DES / unknown | setkey / ctx@1 | key@0 (8B) | void |
| `DES_ecb_encrypt` | 4 | DES / ECB | context_use / ctx@2 | input@0 (8B) | void |
| `DES_cbc_encrypt`, `DES_ncbc_encrypt` | 6 | DES / CBC | context_use / ctx@3 | iv@4 (8B) | void |
| `DES_cfb64_encrypt` | 7 | DES / CFB | context_use / ctx@3 | iv@4 (8B) | void |
| `DES_ofb64_encrypt` | 6 | DES / OFB | context_use / ctx@3 | iv@4 (8B) | void |
| `DES_cfb_encrypt` | 7 | DES / CFB | context_use / ctx@4 | iv@5 (8B); cfb_segment_bits@2 (scalar) | void |
| `DES_ofb_encrypt` | 6 | DES / OFB | context_use / ctx@4 | iv@5 (8B); segment_bits@2 (scalar) | void |
| `mbedtls_aes_setkey_enc` | 3 | AES / unknown | setkey / ctx@0 | key@1 (arg2/8); key_bits@2 (scalar) | mbedtls |
| `mbedtls_aes_setkey_dec` | 3 | AES / unknown | setkey / ctx@0 | key@1 (arg2/8); key_bits@2 (scalar) | mbedtls |
| `mbedtls_aes_crypt_ecb` | 4 | AES / ECB | context_use / ctx@0 | input@2 (16B) | mbedtls |
| `mbedtls_aes_crypt_cbc` | 6 | AES / CBC | context_use / ctx@0 | iv@3 (16B) | mbedtls |
| `mbedtls_aes_crypt_ctr` | 7 | AES / CTR | context_use / ctx@0 | counter_block@3 (16B); stream_block@4 (16B) | mbedtls |
| `mbedtls_aes_crypt_cfb128` | 7 | AES / CFB | context_use / ctx@0 | iv@4 (16B) | mbedtls |
| `mbedtls_aes_crypt_cfb8` | 6 | AES / CFB | context_use / ctx@0 | iv@3 (16B) | mbedtls |
| `mbedtls_aes_crypt_ofb` | 6 | AES / OFB | context_use / ctx@0 | iv@3 (16B) | mbedtls |
| `mbedtls_des_setkey_enc`, `mbedtls_des_setkey_dec` | 2 | DES / unknown | setkey / ctx@0 | key@1 (8B) | mbedtls |
| `mbedtls_des_crypt_ecb` | 3 | DES / ECB | context_use / ctx@0 |  | mbedtls |
| `mbedtls_des_crypt_cbc` | 6 | DES / CBC | context_use / ctx@0 | iv@3 (8B) | mbedtls |
| `mbedtls_arc4_setup` | 3 | RC4 / STREAM | setkey / ctx@0 | key@1 (arg2) | void |
| `mbedtls_arc4_crypt` | 4 | RC4 / STREAM | context_use / ctx@0 |  | mbedtls |
| `mbedtls_chacha20_setkey` | 2 | ChaCha20 / STREAM | setkey / ctx@0 | key@1 (32B) | mbedtls |
| `mbedtls_chacha20_starts` | 3 | ChaCha20 / STREAM | context_use / ctx@0 | nonce@1 (12B); counter@2 (scalar) | mbedtls |
| `mbedtls_chacha20_update` | 4 | ChaCha20 / STREAM | context_use / ctx@0 |  | mbedtls |
| `mbedtls_chacha20_crypt` | 6 | ChaCha20 / STREAM | direct | key@0 (32B); nonce@1 (12B); counter@2 (scalar); input@4 (arg3) | mbedtls |
| `mbedtls_gcm_setkey` | 4 | unknown / GCM | setkey / ctx@0 | key@2 (arg3/8); cipher_id@1 (scalar) | mbedtls |
| `mbedtls_gcm_crypt_and_tag` | 11 | unknown / GCM | context_use / ctx@0 | nonce@3 (arg4); aad@5 (arg6); tag@10 (arg9) | mbedtls |
| `mbedtls_gcm_auth_decrypt` | 10 | unknown / GCM | context_use / ctx@0 | nonce@2 (arg3); aad@4 (arg5); tag@6 (arg7) | mbedtls |
| `crypto_stream_salsa20_xor` | 5 | Salsa20 / STREAM | direct | key@4 (32B); nonce@3 (8B) | zero |
| `crypto_stream_salsa20_xor_ic` | 6 | Salsa20 / STREAM | direct | key@5 (32B); nonce@3 (8B); counter@4 (scalar) | zero |
| `crypto_stream_salsa20` | 4 | Salsa20 / STREAM | direct | key@3 (32B); nonce@2 (8B) | zero |
| `crypto_stream_chacha20_xor` | 5 | ChaCha20 / STREAM | direct | key@4 (32B); nonce@3 (8B) | zero |
| `crypto_stream_chacha20_xor_ic` | 6 | ChaCha20 / STREAM | direct | key@5 (32B); nonce@3 (8B); counter@4 (scalar) | zero |
| `crypto_stream_chacha20` | 4 | ChaCha20 / STREAM | direct | key@3 (32B); nonce@2 (8B) | zero |
| `crypto_stream_chacha20_ietf_xor` | 5 | ChaCha20 / STREAM | direct | key@4 (32B); nonce@3 (12B) | zero |
| `crypto_stream_chacha20_ietf_xor_ic` | 6 | ChaCha20 / STREAM | direct | key@5 (32B); nonce@3 (12B); counter@4 (scalar) | zero |
| `crypto_stream_chacha20_ietf` | 4 | ChaCha20 / STREAM | direct | key@3 (32B); nonce@2 (12B) | zero |
| `crypto_stream_xchacha20_xor` | 5 | XChaCha20 / STREAM | direct | key@4 (32B); nonce@3 (24B) | zero |
| `crypto_stream_xchacha20_xor_ic` | 6 | XChaCha20 / STREAM | direct | key@5 (32B); nonce@3 (24B); counter@4 (scalar) | zero |
| `crypto_stream_xchacha20` | 4 | XChaCha20 / STREAM | direct | key@3 (32B); nonce@2 (24B) | zero |
| `crypto_aead_chacha20poly1305_ietf_encrypt` | 9 | ChaCha20-Poly1305 / AEAD | direct | key@8 (32B); nonce@7 (12B); aad@4 (arg5) | zero |
| `crypto_aead_chacha20poly1305_ietf_decrypt` | 9 | ChaCha20-Poly1305 / AEAD | direct | key@8 (32B); nonce@7 (12B); aad@5 (arg6) | zero |
| `crypto_aead_xchacha20poly1305_ietf_encrypt` | 9 | XChaCha20-Poly1305 / AEAD | direct | key@8 (32B); nonce@7 (24B); aad@4 (arg5) | zero |
| `crypto_aead_xchacha20poly1305_ietf_decrypt` | 9 | XChaCha20-Poly1305 / AEAD | direct | key@8 (32B); nonce@7 (24B); aad@5 (arg6) | zero |
| `crypto_aead_aes256gcm_encrypt` | 9 | AES / GCM | direct | key@8 (32B); nonce@7 (12B); aad@4 (arg5) | zero |
| `crypto_aead_aes256gcm_decrypt` | 9 | AES / GCM | direct | key@8 (32B); nonce@7 (12B); aad@5 (arg6) | zero |
| `nettle_aes128_set_encrypt_key`, `nettle_aes128_set_decrypt_key` | 2 | AES / unknown | setkey / ctx@0 | key@1 (16B) | void |
| `nettle_aes192_set_encrypt_key`, `nettle_aes192_set_decrypt_key` | 2 | AES / unknown | setkey / ctx@0 | key@1 (24B) | void |
| `nettle_aes256_set_encrypt_key`, `nettle_aes256_set_decrypt_key` | 2 | AES / unknown | setkey / ctx@0 | key@1 (32B) | void |
| `AES_init_ctx` | 2 | AES / unknown | setkey / ctx@0 | key@1 (key_length) | void |
| `AES_init_ctx_iv` | 3 | AES / unknown | setkey / ctx@0 | key@1 (key_length); iv@2 (16B) | void |
| `AES_CBC_encrypt_buffer`, `AES_CBC_decrypt_buffer` | 3 | AES / CBC | context_use / ctx@0 |  | void |
| `AES_ECB_encrypt`, `AES_ECB_decrypt` | 2 | AES / ECB | context_use / ctx@0 |  | void |
| `AES_CTR_xcrypt_buffer` | 3 | AES / CTR | context_use / ctx@0 |  | void |
| `RSA_public_encrypt`, `RSA_private_encrypt`, `RSA_public_decrypt`, `RSA_private_decrypt` | 5 | RSA / unknown | rsa_use / ctx@3 | rsa_handle@3 (opaque); rsa_padding@4 (scalar) | positive32 |
| `RSA_set0_key` | 4 | RSA / unknown | rsa_setkey / ctx@0 | n@1 (opaque); e@2 (opaque); d@3 (opaque) | unspecified |
| `BN_bin2bn` | 3 | unknown / unknown | bignum_import | bignum_bytes@0 (arg1) | pointer |
| `BN_set_word` | 2 | unknown / unknown | bignum_word / ctx@0 | word@1 (scalar) | bool |
| `EVP_PKEY_CTX_set_rsa_padding` | 2 | RSA / unknown | rsa_padding / ctx@0 | rsa_padding@1 (scalar) | openssl |
| `EVP_PKEY_CTX_set_rsa_oaep_md`, `EVP_PKEY_CTX_set_rsa_mgf1_md` | 2 | RSA / unknown | rsa_hash / ctx@0 |  | openssl |
| `EVP_PKEY_CTX_set0_rsa_oaep_label` | 3 | RSA / unknown | context_use / ctx@0 | oaep_label@1 (arg2) | openssl |
| `EVP_PKEY_encrypt`, `EVP_PKEY_decrypt` | 5 | unknown / unknown | context_use / ctx@0 |  | openssl |
| `BCryptOpenAlgorithmProvider` | 4 | unknown / unknown | cng_open | algorithm_name@1 (utf16); handle_out@0 (pointer) | ntstatus |
| `BCryptSetProperty` | 5 | unknown / unknown | cng_property / ctx@0 | property_name@1 (utf16); property_data@2 (arg3) | ntstatus |
| `BCryptGenerateSymmetricKey` | 7 | unknown / unknown | cng_key / ctx@0 | key@4 (arg5) | ntstatus |
| `BCryptImportKey` | 9 | unknown / unknown | cng_import / ctx@0 | blob_type@2 (utf16); key_blob@6 (arg7) | ntstatus |
| `BCryptImportKeyPair` | 7 | unknown / unknown | cng_import / ctx@0 | blob_type@2 (utf16); key_blob@4 (arg5) | ntstatus |
| `BCryptEncrypt`, `BCryptDecrypt` | 10 | unknown / unknown | cng_use / ctx@0 | iv@4 (arg5); padding_info@3 (pointer); flags@9 (scalar) | ntstatus |
| `BCryptDestroyKey` | 1 | unknown / unknown | destroy_context / ctx@0 |  | ntstatus |
| `BCryptCloseAlgorithmProvider` | 2 | unknown / unknown | destroy_context / ctx@0 |  | ntstatus |
| `CryptImportKey` | 6 | unknown / unknown | capi_import / ctx@0 | key_blob@1 (arg2) | bool |
| `CryptSetKeyParam` | 4 | unknown / unknown | capi_property / ctx@0 | parameter@1 (scalar); parameter_pointer@2 (pointer) | bool |
| `CryptEncrypt` | 7 | unknown / unknown | capi_use / ctx@0 | final@2 (scalar) | bool |
| `CryptDecrypt` | 6 | unknown / unknown | capi_use / ctx@0 | final@2 (scalar) | bool |
| `CryptDestroyKey` | 1 | unknown / unknown | destroy_context / ctx@0 |  | bool |
| `PKCS5_PBKDF2_HMAC` | 8 | unknown / unknown | kdf | password@0 (arg1); salt@2 (arg3); iterations@4 (scalar); derived_key_length@6 (scalar) | openssl |
| `getrandom` | 3 | unknown / unknown | random | random_output@0 (pointer) | positive |
| `RAND_bytes` | 2 | unknown / unknown | random | random_output@0 (pointer) | openssl |
| `BCryptGenRandom` | 4 | unknown / unknown | random | random_output@1 (pointer) | ntstatus |

## Phần nhận diện descriptor ngoài API profiles

`EVP_aes_{128,192,256}_{ecb,cbc,ctr,cfb128,cfb8,cfb1,ofb,gcm}`, `EVP_des_{ecb,cbc,cfb64,cfb8,cfb1,ofb}`, `EVP_rc4`, `EVP_rc4_40`, `EVP_chacha20`, `EVP_chacha20_poly1305`: getters được partial evaluator nhận diện để nối descriptor vào EVP init. Debug dùng descriptor evidence hoặc EVP fetch observed return, không đoán memory layout của pointer.

EVP_get_cipherbyname/fetch canonical CFB names được map CFB128 cho AES và CFB64 cho DES. API đã đổi tên/dispatch qua unknown function pointer vẫn có thể cần manual binding.

## Những thứ không suy ra tự động

- Mode của code primitive tự viết chỉ từ AES instructions/S-box/TEA delta.
- Raw key từ expanded AES/DES schedule hoặc RC4 state nếu không thấy setup.
- Private RSA key từ opaque pointer/layout nội bộ không được theo dõi.
- File header/trailer, extension, padding/original size, counter endian/packing khi thiếu evidence.
- OSSL_PARAM của EVP _ex2: khi params không NULL, độ dài có thể override được đánh dấu unresolved.
- Đầy đủ mọi API/provider/version; file này là danh sách scope cụ thể.
