// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    path::Path,
    time::{Duration, Instant},
};

use anyhow::Context;
use byte_unit::n_mib_bytes;
use fraction::{Fraction, GenericFraction, ToPrimitive};
use once_cell::sync::Lazy;
use scryptenc::scrypt;
use sysinfo::{RefreshKind, System, SystemExt};
use thiserror::Error;

use crate::cli::{Byte, Rate, Time};

type U128Fraction = GenericFraction<u128>;

const SECOND: Duration = Duration::from_secs(1);

static SYSTEM: Lazy<System> =
    Lazy::new(|| System::new_with_specifics(RefreshKind::new().with_memory()));
static OPERATIONS_PER_SECOND: Lazy<u64> = Lazy::new(get_scrypt_performance);

/// The error type for this module.
#[derive(Debug, Error)]
pub enum Error {
    /// Decrypting files takes too much memory.
    #[error("decrypting files takes too much memory")]
    Memory,

    /// Decrypting files takes too much CPU time.
    #[error("decrypting files takes too much CPU time")]
    CpuTime,

    /// Decrypting files takes too much resources.
    #[error("decrypting files takes too much resources")]
    Resources,
}

/// Gets the encryption parameters.
pub fn get(data: &[u8], path: &Path) -> anyhow::Result<scryptenc::Params> {
    scryptenc::Params::new(data)
        .with_context(|| format!("{} is not a valid scrypt encrypted file", path.display()))
}

/// Prints the encryption parameters.
fn display(n: u64, r: u32, p: u32) {
    let mem_usage =
        byte_unit::Byte::from_bytes(128 * u128::from(n) * u128::from(r)).get_appropriate_unit(true);
    eprintln!("Parameters used: N = {n}; r = {r}; p = {p};");
    eprint!("    Decrypting this file requires at least {mem_usage} of memory");
}

/// Prints the encryption parameters without resources.
fn display_without_resources(log_n: u8, r: u32, p: u32) {
    let n = 1 << log_n;
    display(n, r, p);
    eprint!(".");
}

/// Prints the encryption parameters without resources, with a newline.
pub fn displayln_without_resources(log_n: u8, r: u32, p: u32) {
    display_without_resources(log_n, r, p);
    eprintln!();
}

/// Prints the encryption parameters with resources.
fn display_with_resources(
    log_n: u8,
    r: u32,
    p: u32,
    max_memory: Option<Byte>,
    max_memory_fraction: Rate,
    max_time: Time,
) {
    let n = 1 << log_n;
    let mem_limit = byte_unit::Byte::from_bytes(u128::from(get_memory_to_use(
        max_memory,
        max_memory_fraction,
    )))
    .get_appropriate_unit(true);
    let expected_secs = Duration::from_secs_f64(
        (U128Fraction::from(4 * u128::from(n) * u128::from(r) * u128::from(p))
            / U128Fraction::from(*OPERATIONS_PER_SECOND))
        .to_f64()
        .unwrap_or_else(|| Duration::MAX.as_secs_f64()),
    );
    display(n, r, p);
    eprintln!(" ({mem_limit} available),");
    eprint!("    and will take approximately {expected_secs:.2?} (limit: {max_time:.2?}).");
}

/// Prints the encryption parameters with resources, with a newline.
pub fn displayln_with_resources(
    log_n: u8,
    r: u32,
    p: u32,
    max_memory: Option<Byte>,
    max_memory_fraction: Rate,
    max_time: Time,
) {
    display_with_resources(log_n, r, p, max_memory, max_memory_fraction, max_time);
    eprintln!();
}

/// Returns available memory.
fn get_memory_to_use(max_memory: Option<Byte>, max_memory_fraction: Rate) -> u64 {
    let available_mem = SYSTEM.available_memory();
    let mut mem_limit = (U128Fraction::from(available_mem)
        * U128Fraction::from_fraction(*max_memory_fraction))
    .floor()
    .to_u128()
    .expect("available memory should be an integer");

    if let Some(max_mem) = max_memory.map(|mem| mem.get_bytes()) {
        if max_mem < mem_limit {
            mem_limit = max_mem;
        }
    }

    let min_mem = n_mib_bytes!(1);
    if mem_limit < min_mem {
        mem_limit = min_mem;
    }
    u64::try_from(mem_limit).expect("available memory should be 16 EiB or less")
}

/// Returns the number of times Salsa20/8 cores can be executed per second.
fn get_scrypt_performance() -> u64 {
    let params = scrypt::Params::new(7, 1, 1, scrypt::Params::RECOMMENDED_LEN)
        .expect("encryption parameters should be valid");
    let mut dk = [u8::default(); 1];

    let mut i = u64::default();

    let start = Instant::now();
    let elapsed = loop {
        scrypt::scrypt(Default::default(), Default::default(), &params, &mut dk)
            .expect("derived key size should be non-empty");

        i += 512;

        let elapsed = start.elapsed();
        if elapsed > SECOND {
            break elapsed;
        }
    };

    u64::try_from((u128::from(i) * SECOND.as_nanos()) / elapsed.as_nanos())
        .expect("executions per second of Salsa20/8 cores should be valid as `u64`")
}

/// Creates the encryption parameters from resources.
pub fn new(max_memory: Option<Byte>, max_memory_fraction: Rate, max_time: Time) -> scrypt::Params {
    let mem_limit = get_memory_to_use(max_memory, max_memory_fraction);
    let ops_limit = match (U128Fraction::from(*OPERATIONS_PER_SECOND)
        * U128Fraction::from_fraction(Fraction::from(max_time.as_secs_f64())))
    .floor()
    .to_u128()
    {
        Some(ops_limit) if ops_limit < u128::pow(2, 15) => u128::pow(2, 15),
        Some(ops_limit) => ops_limit,
        _ => {
            panic!("operation limits should be an integer");
        }
    };

    let mut log_n = 1;
    let r = 8;
    let mut p = 1;

    let max_n = if ops_limit < (u128::from(mem_limit) / 32) {
        u64::try_from(ops_limit / (u128::from(r) * 4))
            .expect("`N` parameter should be valid as `u64`")
    } else {
        mem_limit / (u64::from(r) * 128)
    };
    for i in 1..63 {
        let n: u64 = 1 << i;
        if n > (max_n / 2) {
            log_n = i;
            break;
        }
    }

    if ops_limit >= (u128::from(mem_limit) / 32) {
        let n: u64 = 1 << log_n;
        let max_r_p = match u32::try_from((ops_limit / 4) / u128::from(n)) {
            Ok(max_r_p) if max_r_p >= u32::pow(2, 30) => u32::pow(2, 30) - 1,
            Ok(max_r_p) => max_r_p,
            _ => {
                panic!("`r * p` should be less than `2^30`");
            }
        };
        p = max_r_p / r;
    }
    scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
        .expect("encryption parameters should be valid")
}

/// Checks the encryption parameters.
pub fn check(
    max_memory: Option<Byte>,
    max_memory_fraction: Rate,
    max_time: Time,
    log_n: u8,
    r: u32,
    p: u32,
) -> Result<(), Error> {
    let mem_limit = get_memory_to_use(max_memory, max_memory_fraction);
    let ops_limit = (U128Fraction::from(*OPERATIONS_PER_SECOND)
        * U128Fraction::from_fraction(Fraction::from(max_time.as_secs_f64())))
    .floor()
    .to_u128()
    .expect("operation limits should be an integer");

    let n: u64 = 1 << log_n;
    match (
        (mem_limit / n) / u64::from(r) < 128,
        ((ops_limit / u128::from(n)) / u128::from(r)) / u128::from(p) < 4,
    ) {
        (true, true) => Err(Error::Resources),
        (true, false) => Err(Error::Memory),
        (false, true) => Err(Error::CpuTime),
        _ => Ok(()),
    }
}

/// The scrypt parameters used for the encrypted data.
#[cfg(any(
    feature = "cbor",
    feature = "json",
    feature = "msgpack",
    feature = "toml",
    feature = "yaml"
))]
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Params {
    #[serde(rename = "N")]
    n: u64,
    r: u32,
    p: u32,
}

#[cfg(any(
    feature = "cbor",
    feature = "json",
    feature = "msgpack",
    feature = "toml",
    feature = "yaml"
))]
impl Params {
    /// Creates a new `Params`.
    pub fn new(params: scryptenc::Params) -> Self {
        Self {
            n: params.n(),
            r: params.r(),
            p: params.p(),
        }
    }

    /// Serializes the given data structure.
    pub fn to_vec(self, format: crate::cli::Format) -> anyhow::Result<Vec<u8>> {
        #[cfg(any(feature = "toml", feature = "yaml"))]
        use crate::utils::StringExt;

        match format {
            #[cfg(feature = "cbor")]
            crate::cli::Format::Cbor => {
                let mut buf = Vec::new();
                ciborium::ser::into_writer(&self, &mut buf)
                    .context("could not serialize as CBOR")?;
                Ok(buf)
            }
            #[cfg(feature = "json")]
            crate::cli::Format::Json => {
                serde_json::to_vec(&self).context("could not serialize as JSON")
            }
            #[cfg(feature = "msgpack")]
            crate::cli::Format::MessagePack => {
                rmp_serde::to_vec_named(&self).context("could not serialize as MessagePack")
            }
            #[cfg(feature = "toml")]
            crate::cli::Format::Toml => {
                let mut toml = toml::to_string(&self).context("could not serialize as TOML")?;
                toml.remove_newline();
                let toml = toml.into_bytes();
                Ok(toml)
            }
            #[cfg(feature = "yaml")]
            crate::cli::Format::Yaml => {
                let mut yaml =
                    serde_yaml::to_string(&self).context("could not serialize as YAML")?;
                yaml.remove_newline();
                let yaml = yaml.into_bytes();
                Ok(yaml)
            }
        }
    }
}
