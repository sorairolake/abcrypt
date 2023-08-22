// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use anyhow::{bail, Context};
use clap::Parser;
use scryptenc::{scrypt, Decryptor, Encryptor, Error as ScryptencError};

use crate::{
    cli::{Command, Opt},
    input, output, params, password,
};

/// Ensures that there are no conflicts if reading the password from stdin.
fn ensure_stdin_does_not_conflict(path: &Path) -> anyhow::Result<()> {
    if path == Path::new("-") {
        bail!("cannot read both password and input data from stdin");
    }
    Ok(())
}

/// Runs the program and returns the result.
#[allow(clippy::too_many_lines)]
pub fn run() -> anyhow::Result<()> {
    let opt = Opt::parse();

    if let Some(shell) = opt.generate_completion {
        Opt::print_completion(shell);
        return Ok(());
    }

    if let Some(command) = opt.command {
        match command {
            Command::Encrypt(arg) => {
                let input = input::read(&arg.input)?;

                let password = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_tty_once,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => {
                        ensure_stdin_does_not_conflict(&arg.input)?;
                        password::read_password_from_stdin()
                    }
                    (_, _, true, ..) => password::read_password_from_tty_once(),
                    (.., Some(env), _) => password::read_password_from_env(&env),
                    (.., Some(file)) => password::read_password_from_file(&file),
                    _ => password::read_password_from_tty(),
                }?;

                let params = if let (Some(log_n), Some(r), Some(p)) = (arg.log_n, arg.r, arg.p) {
                    scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
                        .expect("encryption parameters should be valid")
                } else {
                    params::new(arg.max_memory, arg.max_memory_fraction, arg.max_time)
                };

                if arg.verbose {
                    if arg.force {
                        params::displayln_without_resources(params.log_n(), params.r(), params.p());
                    } else {
                        params::displayln_with_resources(
                            params.log_n(),
                            params.r(),
                            params.p(),
                            arg.max_memory,
                            arg.max_memory_fraction,
                            arg.max_time,
                        );
                    }
                }

                if !arg.force {
                    params::check(
                        arg.max_memory,
                        arg.max_memory_fraction,
                        arg.max_time,
                        params.log_n(),
                        params.r(),
                        params.p(),
                    )?;
                }

                let cipher = Encryptor::with_params(input, password, params);
                let encrypted = cipher.encrypt_to_vec();

                if let Some(file) = arg.output {
                    output::write_to_file(&file, &encrypted)?;
                } else {
                    output::write_to_stdout(&encrypted)?;
                }
            }
            Command::Decrypt(arg) => {
                let input = input::read(&arg.input)?;

                let password = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => {
                        ensure_stdin_does_not_conflict(&arg.input)?;
                        password::read_password_from_stdin()
                    }
                    (.., Some(env), _) => password::read_password_from_env(&env),
                    (.., Some(file)) => password::read_password_from_file(&file),
                    _ => password::read_password_from_tty_once(),
                }?;

                let params = params::get(&input, &arg.input)?;
                if arg.verbose {
                    if arg.force {
                        params::displayln_without_resources(params.log_n(), params.r(), params.p());
                    } else {
                        params::displayln_with_resources(
                            params.log_n(),
                            params.r(),
                            params.p(),
                            arg.max_memory,
                            arg.max_memory_fraction,
                            arg.max_time,
                        );
                    }
                }

                if !arg.force {
                    params::check(
                        arg.max_memory,
                        arg.max_memory_fraction,
                        arg.max_time,
                        params.log_n(),
                        params.r(),
                        params.p(),
                    )?;
                }

                let cipher = match Decryptor::new(input, password) {
                    c @ Err(ScryptencError::InvalidHeaderMac(_)) => {
                        c.context("password is incorrect")
                    }
                    c => c.with_context(|| {
                        format!("the header in {} is invalid", arg.input.display())
                    }),
                }?;
                let decrypted = cipher
                    .decrypt_to_vec()
                    .with_context(|| format!("{} is corrupted", arg.input.display()))?;

                if let Some(file) = arg.output {
                    output::write_to_file(&file, &decrypted)?;
                } else {
                    output::write_to_stdout(&decrypted)?;
                }
            }
            Command::Information(arg) => {
                let input = input::read(&arg.input)?;

                let params = params::get(&input, &arg.input)?;
                #[cfg(any(
                    feature = "cbor",
                    feature = "json",
                    feature = "msgpack",
                    feature = "toml",
                    feature = "yaml"
                ))]
                if let Some(format) = arg.format {
                    let params = params::Params::new(params);
                    let output = params
                        .to_vec(format)
                        .context("could not output the encryption parameters")?;
                    if let Ok(string) = std::str::from_utf8(&output) {
                        println!("{string}");
                    } else {
                        output::write_to_stdout(&output)?;
                    }
                } else {
                    params::displayln_without_resources(params.log_n(), params.r(), params.p());
                }
                #[cfg(not(any(
                    feature = "cbor",
                    feature = "json",
                    feature = "msgpack",
                    feature = "toml",
                    feature = "yaml"
                )))]
                params::displayln_without_resources(params.log_n(), params.r(), params.p());
            }
        }
    } else {
        unreachable!();
    }
    Ok(())
}
