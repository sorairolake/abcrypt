// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#pragma once

// This file is automatically generated by cbindgen. Don't modify this manually.

#include <stdint.h>

// The number of bytes of the header.
#define ABCRYPT_HEADER_SIZE 148

// The number of bytes of the MAC (authentication tag) of the ciphertext.
#define ABCRYPT_TAG_SIZE 16

// The error code for the abcrypt encrypted data format.
typedef enum abcrypt_error_code {
  // Everything is ok.
  ABCRYPT_ERROR_CODE_OK,
  // General error.
  ABCRYPT_ERROR_CODE_ERROR,
  // The encrypted data was shorter than 164 bytes.
  ABCRYPT_ERROR_CODE_INVALID_LENGTH,
  // The magic number (file signature) was invalid.
  ABCRYPT_ERROR_CODE_INVALID_MAGIC_NUMBER,
  // The version was the unsupported abcrypt version number.
  ABCRYPT_ERROR_CODE_UNSUPPORTED_VERSION,
  // The version was the unrecognized abcrypt version number.
  ABCRYPT_ERROR_CODE_UNKNOWN_VERSION,
  // The Argon2 type were invalid.
  ABCRYPT_ERROR_CODE_INVALID_ARGON2_TYPE,
  // The Argon2 version were invalid.
  ABCRYPT_ERROR_CODE_INVALID_ARGON2_VERSION,
  // The Argon2 parameters were invalid.
  ABCRYPT_ERROR_CODE_INVALID_ARGON2_PARAMS,
  // The Argon2 context was invalid.
  ABCRYPT_ERROR_CODE_INVALID_ARGON2_CONTEXT,
  // The MAC (authentication tag) of the header was invalid.
  ABCRYPT_ERROR_CODE_INVALID_HEADER_MAC,
  // The MAC (authentication tag) of the ciphertext was invalid.
  ABCRYPT_ERROR_CODE_INVALID_MAC,
} abcrypt_error_code;

// The Argon2 parameters used for the encrypted data.
typedef struct abcrypt_params {
  uint32_t memory_cost;
  uint32_t time_cost;
  uint32_t parallelism;
} abcrypt_params;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// Decrypts `ciphertext` and write to `out`.
//
// # Errors
//
// Returns an error if any of the following are true:
//
// - `ciphertext` is shorter than 164 bytes.
// - The magic number is invalid.
// - The version number is the unsupported abcrypt version number.
// - The version number is the unrecognized abcrypt version number.
// - The Argon2 type is invalid.
// - The Argon2 version is invalid.
// - The Argon2 parameters are invalid.
// - The Argon2 context is invalid.
// - The MAC (authentication tag) of the header is invalid.
// - The MAC (authentication tag) of the ciphertext is invalid.
// - One of the parameters is null.
//
// # Safety
//
// Behavior is undefined if any of the following violates the safety conditions
// of `slice::from_raw_parts`:
//
// - `ciphertext` and `ciphertext_len`.
// - `passphrase` and `passphrase_len`.
// - `out` and `out_len`.
enum abcrypt_error_code abcrypt_decrypt(uint8_t *ciphertext,
                                        uintptr_t ciphertext_len,
                                        uint8_t *passphrase,
                                        uintptr_t passphrase_len,
                                        uint8_t *out,
                                        uintptr_t out_len);

// Encrypts `plaintext` and write to `out`.
//
// This uses the recommended Argon2 parameters according to the OWASP Password
// Storage Cheat Sheet. This also uses Argon2id as the Argon2 type and version
// 0x13 as the Argon2 version.
//
// # Errors
//
// Returns an error if any of the following are true:
//
// - The Argon2 context is invalid.
// - One of the parameters is null.
//
// # Safety
//
// Behavior is undefined if any of the following violates the safety conditions
// of `slice::from_raw_parts`:
//
// - `plaintext` and `plaintext_len`.
// - `passphrase` and `passphrase_len`.
// - `out` and `out_len`.
enum abcrypt_error_code abcrypt_encrypt(uint8_t *plaintext,
                                        uintptr_t plaintext_len,
                                        uint8_t *passphrase,
                                        uintptr_t passphrase_len,
                                        uint8_t *out,
                                        uintptr_t out_len);

// Encrypts `plaintext` with the specified Argon2 parameters and write to
// `out`.
//
// This uses Argon2id as the Argon2 type and version 0x13 as the Argon2
// version.
//
// # Errors
//
// Returns an error if any of the following are true:
//
// - The Argon2 parameters are invalid.
// - The Argon2 context is invalid.
// - One of the parameters is null.
//
// # Safety
//
// Behavior is undefined if any of the following violates the safety conditions
// of `slice::from_raw_parts`:
//
// - `plaintext` and `plaintext_len`.
// - `passphrase` and `passphrase_len`.
// - `out` and `out_len`.
enum abcrypt_error_code abcrypt_encrypt_with_params(uint8_t *plaintext,
                                                    uintptr_t plaintext_len,
                                                    uint8_t *passphrase,
                                                    uintptr_t passphrase_len,
                                                    uint8_t *out,
                                                    uintptr_t out_len,
                                                    uint32_t memory_cost,
                                                    uint32_t time_cost,
                                                    uint32_t parallelism);

// Encrypts `plaintext` with the specified Argon2 type, Argon2 version and
// Argon2 parameters and write to `out`.
//
// # Errors
//
// Returns an error if any of the following are true:
//
// - The Argon2 type is invalid.
// - The Argon2 version is invalid.
// - The Argon2 parameters are invalid.
// - The Argon2 context is invalid.
// - One of the parameters is null.
//
// # Safety
//
// Behavior is undefined if any of the following violates the safety conditions
// of `slice::from_raw_parts`:
//
// - `plaintext` and `plaintext_len`.
// - `passphrase` and `passphrase_len`.
// - `out` and `out_len`.
enum abcrypt_error_code abcrypt_encrypt_with_context(uint8_t *plaintext,
                                                     uintptr_t plaintext_len,
                                                     uint8_t *passphrase,
                                                     uintptr_t passphrase_len,
                                                     uint8_t *out,
                                                     uintptr_t out_len,
                                                     uint32_t argon2_type,
                                                     uint32_t argon2_version,
                                                     uint32_t memory_cost,
                                                     uint32_t time_cost,
                                                     uint32_t parallelism);

// Gets a detailed error message.
//
// # Errors
//
// Returns an error if `buf` is null.
//
// # Safety
//
// Behavior is undefined if `buf` and `buf_len` violates the safety conditions
// of `slice::from_raw_parts`.
enum abcrypt_error_code abcrypt_error_message(enum abcrypt_error_code error_code,
                                              uint8_t *buf,
                                              uintptr_t buf_len);

// Returns the number of output bytes of the error message.
uintptr_t abcrypt_error_message_out_len(enum abcrypt_error_code error_code);

// Creates a new Argon2 parameters.
struct abcrypt_params *abcrypt_params_new(void);

// Frees a Argon2 parameters.
//
// # Safety
//
// This must not violate the safety conditions of `Box::from_raw`.
void abcrypt_params_free(struct abcrypt_params *params);

// Reads the Argon2 parameters from `ciphertext`.
//
// # Errors
//
// Returns an error if any of the following are true:
//
// - `ciphertext` is shorter than 164 bytes.
// - The magic number is invalid.
// - The version number is the unrecognized abcrypt version number.
// - The Argon2 parameters are invalid.
// - One of the parameters is null.
//
// # Safety
//
// Behavior is undefined if `ciphertext` and `ciphertext_len` violates the
// safety conditions of `slice::from_raw_parts`.
enum abcrypt_error_code abcrypt_params_read(uint8_t *ciphertext,
                                            uintptr_t ciphertext_len,
                                            struct abcrypt_params *params);

// Gets memory size in KiB.
//
// Returns `0` if `params` is null.
uint32_t abcrypt_params_memory_cost(struct abcrypt_params *params);

// Gets number of iterations.
//
// Returns `0` if `params` is null.
uint32_t abcrypt_params_time_cost(struct abcrypt_params *params);

// Gets degree of parallelism.
//
// Returns `0` if `params` is null.
uint32_t abcrypt_params_parallelism(struct abcrypt_params *params);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
