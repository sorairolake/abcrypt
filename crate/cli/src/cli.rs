// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    ffi::OsString,
    fmt,
    io::{self, Write},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use anyhow::anyhow;
use byte_unit::{n_eib_bytes, n_mib_bytes};
use clap::{
    value_parser, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint,
};
use clap_complete::Generator;
use fraction::{Fraction, Zero};

#[derive(Debug, Parser)]
#[command(
    name("rscrypt"),
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
    #[command(name("enc"))]
    Encrypt(Encrypt),

    /// Decrypt files.
    #[command(name("dec"))]
    Decrypt(Decrypt),

    /// Provides information about the encryption parameters.
    #[command(name("info"))]
    Information(Information),
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
#[command(
    group(ArgGroup::new("password")),
    group(
        ArgGroup::new("resources")
            .multiple(true)
            .conflicts_with("force")
            .conflicts_with("parameters")
    ),
    group(ArgGroup::new("parameters").multiple(true))
)]
pub struct Encrypt {
    /// Force the encryption to proceed even if it requires an excessive amount
    /// of resources.
    #[arg(short, long, requires("parameters"))]
    pub force: bool,

    /// Use at most the specified bytes of RAM to compute the derived key.
    #[arg(short('M'), long, value_name("BYTE"), group("resources"))]
    pub max_memory: Option<Byte>,

    /// Use at most the specified fraction of the available RAM to compute the
    /// derived key.
    #[arg(
        short,
        long,
        default_value("0.125"),
        value_name("RATE"),
        group("resources")
    )]
    pub max_memory_fraction: Rate,

    /// Use at most the specified duration of CPU time to compute the derived
    /// key.
    #[arg(
        short('t'),
        long,
        default_value("5s"),
        value_name("DURATION"),
        group("resources")
    )]
    pub max_time: Time,

    /// Set the work parameter N.
    #[arg(
        value_parser(value_parser!(u8).range(10..=40)),
        long,
        requires("r"),
        requires("p"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub log_n: Option<u8>,

    /// Set the work parameter r.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        requires("log_n"),
        requires("p"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub r: Option<u32>,

    /// Set the work parameter p.
    #[arg(
        value_parser(value_parser!(u32).range(1..=32)),
        short,
        requires("log_n"),
        requires("r"),
        value_name("VALUE"),
        group("parameters")
    )]
    pub p: Option<u32>,

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

    /// Print encryption parameters and resource limits.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from stdin.
    #[arg(value_name("INFILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,

    /// Output file.
    ///
    /// If [OUTFILE] is not specified, the result will be write to stdout.
    #[arg(value_name("OUTFILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
#[command(
    group(ArgGroup::new("password")),
    group(ArgGroup::new("resources").multiple(true).conflicts_with("force"))
)]
pub struct Decrypt {
    /// Force the decryption to proceed even if it requires an excessive amount
    /// of resources.
    #[arg(short, long)]
    pub force: bool,

    /// Use at most the specified bytes of RAM to compute the derived key.
    #[arg(short('M'), long, value_name("BYTE"), group("resources"))]
    pub max_memory: Option<Byte>,

    /// Use at most the specified fraction of the available RAM to compute the
    /// derived key.
    #[arg(
        short,
        long,
        default_value("0.5"),
        value_name("RATE"),
        group("resources")
    )]
    pub max_memory_fraction: Rate,

    /// Use at most the specified duration of CPU time to compute the derived
    /// key.
    #[arg(
        short('t'),
        long,
        default_value("300s"),
        value_name("DURATION"),
        group("resources")
    )]
    pub max_time: Time,

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

    /// Print encryption parameters and resource limits.
    #[arg(short, long)]
    pub verbose: bool,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from stdin.
    #[arg(value_name("INFILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,

    /// Output file.
    ///
    /// If [OUTFILE] is not specified, the result will be write to stdout.
    #[arg(value_name("OUTFILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct Information {
    /// Output format.
    #[cfg(any(
        feature = "cbor",
        feature = "json",
        feature = "msgpack",
        feature = "toml",
        feature = "yaml"
    ))]
    #[arg(short, long, value_enum, value_name("FORMAT"), ignore_case(true))]
    pub format: Option<Format>,

    /// Input file.
    ///
    /// If "-" is specified, data will be read from stdin.
    #[arg(value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub input: PathBuf,
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

/// Amount of RAM.
#[derive(Clone, Copy, Debug)]
pub struct Byte(byte_unit::Byte);

impl Deref for Byte {
    type Target = byte_unit::Byte;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Byte {
    type Err = anyhow::Error;

    fn from_str(bytes: &str) -> anyhow::Result<Self> {
        match byte_unit::Byte::from_str(bytes) {
            Ok(b) if b.get_bytes() < n_mib_bytes!(1) => {
                Err(anyhow!("amount of RAM is less than 1 MiB"))
            }
            Ok(b) if b.get_bytes() > n_eib_bytes!(16) => {
                Err(anyhow!("amount of RAM is more than 16 EiB"))
            }
            Err(err) => Err(anyhow!("amount of RAM is not a valid value: {err}")),
            Ok(b) => Ok(Self(b)),
        }
    }
}

/// Fraction of the available RAM.
#[derive(Clone, Copy, Debug)]
pub struct Rate(Fraction);

impl Deref for Rate {
    type Target = Fraction;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Rate {
    type Err = anyhow::Error;

    fn from_str(rate: &str) -> anyhow::Result<Self> {
        match Fraction::from_str(rate) {
            Ok(r) if r == Fraction::zero() => Err(anyhow!("fraction is 0")),
            Ok(r) if r > Fraction::from(0.5) => Err(anyhow!("fraction is more than 0.5")),
            Err(err) => Err(anyhow!("fraction is not a valid number: {err}")),
            Ok(r) => Ok(Self(r)),
        }
    }
}

/// CPU time.
#[derive(Clone, Copy)]
pub struct Time(Duration);

impl fmt::Debug for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for Time {
    type Target = Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(duration: &str) -> anyhow::Result<Self> {
        match humantime::Duration::from_str(duration) {
            Ok(d) => Ok(Self(*d)),
            Err(err) => Err(anyhow!("time is not a valid value: {err}")),
        }
    }
}

#[cfg(any(
    feature = "cbor",
    feature = "json",
    feature = "msgpack",
    feature = "toml",
    feature = "yaml"
))]
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    /// Concise Binary Object Representation.
    #[cfg(feature = "cbor")]
    Cbor,

    /// JavaScript Object Notation.
    #[cfg(feature = "json")]
    Json,

    /// MessagePack.
    #[cfg(feature = "msgpack")]
    #[value(name("msgpack"))]
    MessagePack,

    /// Tom's Obvious Minimal Language.
    #[cfg(feature = "toml")]
    Toml,

    /// YAML.
    #[cfg(feature = "yaml")]
    Yaml,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_app() {
        Opt::command().debug_assert();
    }
}
