// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use abcrypt::{argon2, Decryptor, Encryptor};
use anyhow::{bail, Context};
use clap::Parser;

use crate::{
    cli::{Command, Opt},
    input, output, params, password,
};

/// Ensures that there are no conflicts if reading the password from stdin.
fn ensure_stdin_does_not_conflict(path: Option<&Path>) -> anyhow::Result<()> {
    if path.is_none() {
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
                if arg.passphrase_from_stdin {
                    ensure_stdin_does_not_conflict(arg.input.as_deref())?;
                }
                let input = input::read(arg.input.as_deref())?;

                let password = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_tty_once,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => password::read_password_from_stdin(),
                    (_, _, true, ..) => password::read_password_from_tty_once(),
                    (.., Some(env), _) => password::read_password_from_env(&env),
                    (.., Some(file)) => password::read_password_from_file(&file),
                    _ => password::read_password_from_tty(),
                }?;

                let params =
                    argon2::Params::new(arg.memory_size, arg.iterations, arg.parallelism, None)
                        .map_err(abcrypt::Error::InvalidArgon2Params)?;

                if arg.verbose {
                    params::displayln(params.m_cost(), params.t_cost(), params.p_cost());
                }

                let cipher = Encryptor::with_params(input, password, params)?;
                let encrypted = cipher.encrypt_to_vec();

                if let Some(file) = arg.output {
                    output::write_to_file(&file, &encrypted)?;
                } else {
                    output::write_to_stdout(&encrypted)?;
                }
            }
            Command::Decrypt(arg) => {
                if arg.passphrase_from_stdin {
                    ensure_stdin_does_not_conflict(arg.input.as_deref())?;
                }
                let input = input::read(arg.input.as_deref())?;

                let password = match (
                    arg.passphrase_from_tty,
                    arg.passphrase_from_stdin,
                    arg.passphrase_from_env,
                    arg.passphrase_from_file,
                ) {
                    (_, true, ..) => password::read_password_from_stdin(),
                    (.., Some(env), _) => password::read_password_from_env(&env),
                    (.., Some(file)) => password::read_password_from_file(&file),
                    _ => password::read_password_from_tty_once(),
                }?;

                let params = params::get(&input)?;
                if arg.verbose {
                    params::displayln(params.m_cost(), params.t_cost(), params.p_cost());
                }

                let cipher = match Decryptor::new(input, password) {
                    c @ Err(abcrypt::Error::InvalidHeaderMac(_)) => {
                        c.context("password is incorrect")
                    }
                    c => c.context("the header in the encrypted data is invalid"),
                }?;
                let decrypted = cipher
                    .decrypt_to_vec()
                    .context("the encrypted data is corrupted")?;

                if let Some(file) = arg.output {
                    output::write_to_file(&file, &decrypted)?;
                } else {
                    output::write_to_stdout(&decrypted)?;
                }
            }
            Command::Information(arg) => {
                let input = input::read(arg.input.as_deref())?;

                let params = params::get(&input)?;
                #[cfg(feature = "json")]
                if arg.json {
                    let params = params::Params::new(&params);
                    let output = params
                        .to_vec()
                        .context("could not output the encryption parameters")?;
                    if let Ok(string) = std::str::from_utf8(&output) {
                        println!("{string}");
                    } else {
                        output::write_to_stdout(&output)?;
                    }
                    return Ok(());
                }
                params::displayln(params.m_cost(), params.t_cost(), params.p_cost());
            }
        }
    } else {
        unreachable!();
    }
    Ok(())
}
