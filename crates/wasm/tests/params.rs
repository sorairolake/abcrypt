// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abcrypt_wasm::Params;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

// Generated using `abcrypt` crate version 0.1.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.abcrypt");

#[wasm_bindgen_test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[wasm_bindgen_test]
fn memory_cost() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.memory_cost(), 32);
}

#[wasm_bindgen_test]
fn time_cost() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.time_cost(), 3);
}

#[wasm_bindgen_test]
fn parallelism() {
    let params = Params::new(TEST_DATA_ENC).map_err(JsValue::from).unwrap();
    assert_eq!(params.parallelism(), 4);
}
