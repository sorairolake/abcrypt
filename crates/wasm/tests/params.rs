// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abcrypt_wasm::Params;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

// Generated using `abcrypt` crate version 0.4.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/v1/argon2id/v0x13/data.txt.abcrypt");

#[wasm_bindgen_test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[wasm_bindgen_test]
fn memory_cost() {
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.memory_cost(), 47104);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.memory_cost(), 19456);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.memory_cost(), 12288);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.memory_cost(), 9216);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.memory_cost(), 7168);
    }
    {
        let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
        assert_eq!(params.memory_cost(), 32);
    }
}

#[wasm_bindgen_test]
fn time_cost() {
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.time_cost(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.time_cost(), 2);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.time_cost(), 3);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.time_cost(), 4);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.time_cost(), 5);
    }
    {
        let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
        assert_eq!(params.time_cost(), 3);
    }
}

#[wasm_bindgen_test]
fn parallelism() {
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt"))
            .map_err(JsValue::from)
            .unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
        assert_eq!(params.parallelism(), 4);
    }
}
