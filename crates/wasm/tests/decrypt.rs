// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const PASSPHRASE: &[u8] = b"passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");
// Generated using `abcrypt` crate version 0.4.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/v1/argon2id/v0x13/data.txt.abcrypt");

#[wasm_bindgen_test]
fn success() {
    {
        let plaintext = abcrypt_wasm::decrypt(
            include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .map_err(JsValue::from)
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt_wasm::decrypt(
            include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .map_err(JsValue::from)
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt_wasm::decrypt(
            include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .map_err(JsValue::from)
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt_wasm::decrypt(
            include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .map_err(JsValue::from)
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt_wasm::decrypt(
            include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .map_err(JsValue::from)
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt_wasm::decrypt(TEST_DATA_ENC, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
}

#[wasm_bindgen_test]
fn incorrect_passphrase() {
    let result = abcrypt_wasm::decrypt(TEST_DATA_ENC, b"password");
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_input_length() {
    {
        let data =
            vec![u8::default(); (abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()) - 1];
        let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }

    {
        let data = vec![u8::default(); abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()];
        let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }
}

#[wasm_bindgen_test]
fn invalid_magic_number() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[0] = u32::from('b').try_into().unwrap();
    let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn unsupported_version() {
    let result = abcrypt_wasm::decrypt(include_bytes!("data/v0/data.txt.abcrypt"), PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn unknown_version() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[7] = 2;
    let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_params() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();

    {
        data[16..20].copy_from_slice(&u32::to_le_bytes(7));
        let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }

    {
        data[20..24].copy_from_slice(&u32::to_le_bytes(0));
        let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }

    {
        data[24..28].copy_from_slice(&u32::pow(2, 24).to_le_bytes());
        let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
        assert!(result.is_err());
    }
}

#[wasm_bindgen_test]
fn invalid_header_mac() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let mut header_mac: [u8; 64] = data[84..148].try_into().unwrap();
    header_mac.reverse();
    data[84..148].copy_from_slice(&header_mac);
    let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}

#[wasm_bindgen_test]
fn invalid_mac() {
    let data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let start_mac = data.len() - abcrypt_wasm::tag_size();
    let mut data = data;
    let mut mac = data[start_mac..].to_vec();
    mac.reverse();
    data[start_mac..].copy_from_slice(&mac);
    let result = abcrypt_wasm::decrypt(&data, PASSPHRASE);
    assert!(result.is_err());
}
