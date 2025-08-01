// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abcrypt::Params;

// Generated using `abcrypt` crate version 0.4.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/v1/argon2id/v0x13/data.txt.abcrypt");

#[test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[test]
fn memory_cost() {
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.memory_cost(), 47104);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt")).unwrap();
        assert_eq!(params.memory_cost(), 19456);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.memory_cost(), 12288);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt")).unwrap();
        assert_eq!(params.memory_cost(), 9216);
    }
    {
        let params =
            Params::new(include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.memory_cost(), 7168);
    }
    {
        let params = Params::new(TEST_DATA_ENC).unwrap();
        assert_eq!(params.memory_cost(), 32);
    }
}

#[test]
fn time_cost() {
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.time_cost(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt")).unwrap();
        assert_eq!(params.time_cost(), 2);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.time_cost(), 3);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt")).unwrap();
        assert_eq!(params.time_cost(), 4);
    }
    {
        let params =
            Params::new(include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.time_cost(), 5);
    }
    {
        let params = Params::new(TEST_DATA_ENC).unwrap();
        assert_eq!(params.time_cost(), 3);
    }
}

#[test]
fn parallelism() {
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt")).unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt")).unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params =
            Params::new(include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt")).unwrap();
        assert_eq!(params.parallelism(), 1);
    }
    {
        let params = Params::new(TEST_DATA_ENC).unwrap();
        assert_eq!(params.parallelism(), 4);
    }
}

#[cfg(feature = "serde")]
#[test]
fn serialize() {
    use serde_test::{Token, assert_ser_tokens};

    assert_ser_tokens(
        &Params::new(TEST_DATA_ENC).unwrap(),
        &[
            Token::Struct {
                name: "Params",
                len: 3,
            },
            Token::Str("memoryCost"),
            Token::U32(32),
            Token::Str("timeCost"),
            Token::U32(3),
            Token::Str("parallelism"),
            Token::U32(4),
            Token::StructEnd,
        ],
    );
}

#[cfg(feature = "serde")]
#[test]
fn serialize_json() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(
        serde_json::to_string(&params).unwrap(),
        r#"{"memoryCost":32,"timeCost":3,"parallelism":4}"#
    );
}
