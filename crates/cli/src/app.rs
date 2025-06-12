// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use abcrypt::{Argon2, Decryptor, argon2};
use anyhow::{Context, bail};
use clap::Parser;

use crate::{
    cli::{Command, Opt},
    input, output, params, passphrase,
};

/// Ensures that there are no conflicts if reading the passphrase from standard
/// input.
fn ensure_stdin_does_not_conflict(path: Option<&Path>) -> anyhow::Result<()> {
    if path.is_none() {
        bail!("cannot read both passphrase and input data from standard input");
    }
    Ok(())
}

/// Runs the program and returns the result.
#[allow(clippy::too_many_lines)]
pub fn run() -> anyhow::Result<()> {
    let opt = Opt::parse();

    match opt.command {
        Command::Encrypt(arg) => {
            if arg.passphrase_from_stdin {
                ensure_stdin_does_not_conflict(arg.input.as_deref())?;
            }
            let input = input::read(arg.input.as_deref())?;

            let passphrase = match (
                arg.passphrase_from_tty,
                arg.passphrase_from_stdin,
                arg.passphrase_from_tty_once,
                arg.passphrase_from_env,
                arg.passphrase_from_file,
            ) {
                (_, true, ..) => passphrase::read_passphrase_from_stdin(),
                (_, _, true, ..) => passphrase::read_passphrase_from_tty_once(),
                (.., Some(env), _) => passphrase::read_passphrase_from_env(&env),
                (.., Some(file)) => passphrase::read_passphrase_from_file(&file),
                _ => passphrase::read_passphrase_from_tty(),
            }?;

            let params =
                argon2::Params::new(*arg.memory_cost, *arg.time_cost, *arg.parallelism, None)
                    .map_err(abcrypt::Error::InvalidArgon2Params)?;

            if arg.verbose {
                params::displayln(params.m_cost(), params.t_cost(), params.p_cost());
            }

            let ciphertext = abcrypt::encrypt_with_context(
                input,
                passphrase,
                arg.argon2_type.into(),
                arg.argon2_version.into(),
                params,
            )?;

            if let Some(file) = arg.output {
                output::write_to_file(&file, &ciphertext)?;
            } else {
                output::write_to_stdout(&ciphertext)?;
            }
        }
        Command::Decrypt(arg) => {
            if arg.passphrase_from_stdin {
                ensure_stdin_does_not_conflict(arg.input.as_deref())?;
            }
            let input = input::read(arg.input.as_deref())?;

            let passphrase = match (
                arg.passphrase_from_tty,
                arg.passphrase_from_stdin,
                arg.passphrase_from_env,
                arg.passphrase_from_file,
            ) {
                (_, true, ..) => passphrase::read_passphrase_from_stdin(),
                (.., Some(env), _) => passphrase::read_passphrase_from_env(&env),
                (.., Some(file)) => passphrase::read_passphrase_from_file(&file),
                _ => passphrase::read_passphrase_from_tty_once(),
            }?;

            let params = params::get(&input)?;
            if arg.verbose {
                params::displayln(
                    params.memory_cost(),
                    params.time_cost(),
                    params.parallelism(),
                );
            }

            let cipher = match Decryptor::new(&input, passphrase) {
                c @ Err(abcrypt::Error::InvalidHeaderMac(_)) => {
                    c.context("passphrase is incorrect")
                }
                c => c.context("the header in the encrypted data is invalid"),
            }?;
            let plaintext = cipher
                .decrypt_to_vec()
                .context("the encrypted data is corrupted")?;

            if let Some(file) = arg.output {
                output::write_to_file(&file, &plaintext)?;
            } else {
                output::write_to_stdout(&plaintext)?;
            }
        }
        Command::Argon2(arg) => {
            let input = input::read(arg.input.as_deref())?;

            let argon2 =
                Argon2::new(input).context("data is not a valid abcrypt encrypted file")?;
            eprintln!("Type: {:?}", argon2.variant());
            eprintln!("Version: {:#x}", u32::from(argon2.version()));
        }
        Command::Information(arg) => {
            let input = input::read(arg.input.as_deref())?;

            let params = params::get(&input)?;
            #[cfg(feature = "json")]
            if arg.json {
                let output =
                    serde_json::to_string(&params).context("could not serialize as JSON")?;
                println!("{output}");
                return Ok(());
            }
            params::displayln(
                params.memory_cost(),
                params.time_cost(),
                params.parallelism(),
            );
        }
        Command::Completion(arg) => {
            Opt::print_completion(arg.shell);
        }
    }
    Ok(())
}
