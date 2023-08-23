// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
};

use abcrypt::argon2::Params;
use clap::{ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::Generator;

#[derive(Debug, Parser)]
#[command(
    name("abcrypt"),
    version,
    about,
    max_term_width(100),
    propagate_version(true),
    arg_required_else_help(true),
    args_conflicts_with_subcommands(true)
)]
pub struct Opt {
    /// Generate shell completion.
    ///
    /// The completion is output to stdout.
    #[arg(long, value_enum, value_name("SHELL"))]
    pub generate_completion: Option<Shell>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt files.
    #[command(visible_aliases(["enc", "e"]))]
    Encrypt(Encrypt),

    /// Decrypt files.
    #[command(visible_aliases(["dec", "d"]))]
    Decrypt(Decrypt),

    /// Provides information about the encryption parameters.
    #[command(visible_aliases(["info", "i"]))]
    Information(Information),
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
#[command(group(ArgGroup::new("password")))]
pub struct Encrypt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,

    /// Set the memory size in KiB.
    #[arg(
        short,
        long,
        default_value_t = Params::DEFAULT_M_COST,
        value_name("NUM")
    )]
    pub memory_size: u32,

    /// Set the number of iterations.
    #[arg(
        short('t'),
        long,
        default_value_t = Params::DEFAULT_T_COST,
        value_name("NUM")
    )]
    pub iterations: u32,

    /// Set the degree of parallelism.
    #[arg(
        short,
        long,
        default_value_t = Params::DEFAULT_P_COST,
        value_name("NUM")
    )]
    pub parallelism: u32,

    /// Read the password from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("password"))]
    pub passphrase_from_tty: bool,

    /// Read the password from stdin.
    #[arg(long, group("password"))]
    pub passphrase_from_stdin: bool,

    /// Read the password from /dev/tty only once.
    #[arg(long, group("password"))]
    pub passphrase_from_tty_once: bool,

    /// Read the password from the environment variable.
    ///
    /// Note that storing a password in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("password"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the password from the file.
    ///
    /// Note that storing a password in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("password")
    )]
    pub passphrase_from_file: Option<PathBuf>,

    /// Print the encryption parameters.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from stdin.
    #[arg(value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub input: Option<PathBuf>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
#[command(group(ArgGroup::new("password")))]
pub struct Decrypt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,

    /// Read the password from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("password"))]
    pub passphrase_from_tty: bool,

    /// Read the password from stdin.
    #[arg(long, group("password"))]
    pub passphrase_from_stdin: bool,

    /// Read the password from the environment variable.
    ///
    /// Note that storing a password in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("password"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the password from the file.
    ///
    /// Note that storing a password in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("password")
    )]
    pub passphrase_from_file: Option<PathBuf>,

    /// Print the encryption parameters.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from stdin.
    #[arg(value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub input: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Information {
    /// Output the encryption parameters as JSON.
    #[cfg(feature = "json")]
    #[arg(short, long)]
    pub json: bool,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from stdin.
    #[arg(value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub input: Option<PathBuf>,
}

impl Opt {
    /// Generates shell completion and print it.
    pub fn print_completion(gen: impl Generator) {
        clap_complete::generate(
            gen,
            &mut Self::command(),
            Self::command().get_name(),
            &mut io::stdout(),
        );
    }
}

#[derive(Clone, Debug, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Shell {
    /// Bash.
    Bash,

    /// Elvish.
    Elvish,

    /// fish.
    Fish,

    /// Nushell.
    Nushell,

    /// PowerShell.
    PowerShell,

    /// Zsh.
    Zsh,
}

impl Generator for Shell {
    fn file_name(&self, name: &str) -> String {
        match self {
            Self::Bash => clap_complete::Shell::Bash.file_name(name),
            Self::Elvish => clap_complete::Shell::Elvish.file_name(name),
            Self::Fish => clap_complete::Shell::Fish.file_name(name),
            Self::Nushell => clap_complete_nushell::Nushell.file_name(name),
            Self::PowerShell => clap_complete::Shell::PowerShell.file_name(name),
            Self::Zsh => clap_complete::Shell::Zsh.file_name(name),
        }
    }

    fn generate(&self, cmd: &clap::Command, buf: &mut dyn Write) {
        match self {
            Self::Bash => clap_complete::Shell::Bash.generate(cmd, buf),
            Self::Elvish => clap_complete::Shell::Elvish.generate(cmd, buf),
            Self::Fish => clap_complete::Shell::Fish.generate(cmd, buf),
            Self::Nushell => clap_complete_nushell::Nushell.generate(cmd, buf),
            Self::PowerShell => clap_complete::Shell::PowerShell.generate(cmd, buf),
            Self::Zsh => clap_complete::Shell::Zsh.generate(cmd, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        Opt::command().debug_assert();
    }
}
