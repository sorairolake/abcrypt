// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abcrypt_wasm::Params;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

const PASSPHRASE: &[u8] = b"passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[wasm_bindgen_test]
fn success() {
    let ciphertext = abcrypt_wasm::encrypt(TEST_DATA, PASSPHRASE)
        .map_err(JsValue::from)
        .unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(
        ciphertext.len(),
        TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
    );

    let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
    assert_eq!(params.memory_cost(), 19456);
    assert_eq!(params.time_cost(), 2);
    assert_eq!(params.parallelism(), 1);

    let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[wasm_bindgen_test]
fn success_with_params() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(
        ciphertext.len(),
        TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
    );

    let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
    assert_eq!(params.memory_cost(), 32);
    assert_eq!(params.time_cost(), 3);
    assert_eq!(params.parallelism(), 4);

    let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[wasm_bindgen_test]
fn success_with_context() {
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 0, 0x10, 47104, 1, 1)
                .map_err(JsValue::from)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(
            ciphertext.len(),
            TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
        );

        let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 47104);
        assert_eq!(params.time_cost(), 1);
        assert_eq!(params.parallelism(), 1);

        let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 0, 0x13, 19456, 2, 1)
                .map_err(JsValue::from)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(
            ciphertext.len(),
            TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
        );

        let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 19456);
        assert_eq!(params.time_cost(), 2);
        assert_eq!(params.parallelism(), 1);

        let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 1, 0x10, 12288, 3, 1)
                .map_err(JsValue::from)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(
            ciphertext.len(),
            TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
        );

        let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 12288);
        assert_eq!(params.time_cost(), 3);
        assert_eq!(params.parallelism(), 1);

        let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 1, 0x13, 9216, 4, 1)
                .map_err(JsValue::from)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(
            ciphertext.len(),
            TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
        );

        let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 9216);
        assert_eq!(params.time_cost(), 4);
        assert_eq!(params.parallelism(), 1);

        let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 2, 0x10, 7168, 5, 1)
                .map_err(JsValue::from)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(
            ciphertext.len(),
            TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
        );

        let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 7168);
        assert_eq!(params.time_cost(), 5);
        assert_eq!(params.parallelism(), 1);

        let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 2, 0x10, 32, 3, 4)
                .map_err(JsValue::from)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(
            ciphertext.len(),
            TEST_DATA.len() + abcrypt_wasm::header_size() + abcrypt_wasm::tag_size()
        );

        let params = Params::new(&ciphertext).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 32);
        assert_eq!(params.time_cost(), 3);
        assert_eq!(params.parallelism(), 4);

        let plaintext = abcrypt_wasm::decrypt(&ciphertext, PASSPHRASE)
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
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
    assert_eq!(ciphertext[7], 1);
}

#[wasm_bindgen_test]
fn argon2_type() {
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 0, 0x13, 32, 3, 4)
                .map_err(JsValue::from)
                .unwrap();
        assert_eq!(&ciphertext[8..12], u32::to_le_bytes(0));
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 1, 0x13, 32, 3, 4)
                .map_err(JsValue::from)
                .unwrap();
        assert_eq!(&ciphertext[8..12], u32::to_le_bytes(1));
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 2, 0x13, 32, 3, 4)
                .map_err(JsValue::from)
                .unwrap();
        assert_eq!(&ciphertext[8..12], u32::to_le_bytes(2));
    }
}

#[wasm_bindgen_test]
fn argon2_version() {
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 2, 0x10, 32, 3, 4)
                .map_err(JsValue::from)
                .unwrap();
        assert_eq!(&ciphertext[12..16], u32::to_le_bytes(0x10));
    }
    {
        let ciphertext =
            abcrypt_wasm::encrypt_with_context(TEST_DATA, PASSPHRASE, 2, 0x13, 32, 3, 4)
                .map_err(JsValue::from)
                .unwrap();
        assert_eq!(&ciphertext[12..16], u32::to_le_bytes(0x13));
    }
}

#[wasm_bindgen_test]
fn memory_cost() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[16..20], u32::to_le_bytes(32));
}

#[wasm_bindgen_test]
fn time_cost() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[20..24], u32::to_le_bytes(3));
}

#[wasm_bindgen_test]
fn parallelism() {
    let ciphertext = abcrypt_wasm::encrypt_with_params(TEST_DATA, PASSPHRASE, 32, 3, 4)
        .map_err(JsValue::from)
        .unwrap();
    assert_eq!(&ciphertext[24..28], u32::to_le_bytes(4));
}
