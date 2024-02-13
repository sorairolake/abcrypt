// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const PASSPHRASE: &[u8] = b"passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[wasm_bindgen_test]
fn success() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(
        ciphertext.len(),
        TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
    );

    let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[wasm_bindgen_test]
fn minimum_output_length() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(&[], PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(
        ciphertext.len(),
        abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
    );
}

#[wasm_bindgen_test]
fn magic_number() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[..7], b"abcrypt");
}

#[wasm_bindgen_test]
fn version() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(ciphertext[7], 0);
}

#[wasm_bindgen_test]
fn memory_cost() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[8..12], u32::to_le_bytes(32));
}

#[wasm_bindgen_test]
fn time_cost() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[12..16], u32::to_le_bytes(3));
}

#[wasm_bindgen_test]
fn parallelism() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[16..20], u32::to_le_bytes(4));
}
