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
};

use abcrypt::argon2::Params;
use anyhow::anyhow;
use byte_unit::{Byte, KIBIBYTE};
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
#[command(group(ArgGroup::new("passphrase")))]
pub struct Encrypt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,

    /// Set the memory size in bytes.
    ///
    /// <BYTE> can be suffixed with the symbol (B) and the byte prefix (such as
    /// Ki and M). If only a numeric value is specified for <BYTE>, it is the
    /// same as specifying the symbol without the byte prefix. Note that <BYTE>
    /// that is not multiples of 1 KiB is truncated toward zero to the nearest
    /// it.
    #[arg(short, long, default_value_t, value_name("BYTE"))]
    pub memory_size: MemorySize,

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

    /// Read the passphrase from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from stdin.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from /dev/tty only once.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty_once: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("passphrase"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("passphrase")
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
#[command(group(ArgGroup::new("passphrase")))]
pub struct Decrypt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"), value_hint(ValueHint::FilePath))]
    pub output: Option<PathBuf>,

    /// Read the passphrase from /dev/tty.
    ///
    /// This is the default behavior.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_tty: bool,

    /// Read the passphrase from stdin.
    #[arg(long, group("passphrase"))]
    pub passphrase_from_stdin: bool,

    /// Read the passphrase from the environment variable.
    ///
    /// Note that storing a passphrase in an environment variable can be a
    /// security risk.
    #[arg(long, value_name("VAR"), group("passphrase"))]
    pub passphrase_from_env: Option<OsString>,

    /// Read the passphrase from the file.
    ///
    /// Note that storing a passphrase in a file can be a security risk.
    #[arg(
        long,
        value_name("FILE"),
        value_hint(ValueHint::FilePath),
        group("passphrase")
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

/// Memory size in 1 KiB memory blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemorySize(u32);

impl MemorySize {
    /// Minimum number of 1 KiB memory blocks.
    const MIN: Self = Self(Params::MIN_M_COST);

    /// Maximum number of 1 KiB memory blocks.
    const MAX: Self = Self(Params::MAX_M_COST);
}

impl Default for MemorySize {
    fn default() -> Self {
        Self(Params::DEFAULT_M_COST)
    }
}

impl Deref for MemorySize {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MemorySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Byte::from_bytes(u64::from(self.0) * KIBIBYTE)
            .get_appropriate_unit(true)
            .fmt(f)
    }
}

impl FromStr for MemorySize {
    type Err = anyhow::Error;

    fn from_str(byte: &str) -> anyhow::Result<Self> {
        let byte = Byte::from_str(byte)
            .map(|b| b.get_bytes())
            .map_err(anyhow::Error::from)?;
        match u32::try_from(byte / KIBIBYTE) {
            Ok(kibibyte) if (Params::MIN_M_COST..=Params::MAX_M_COST).contains(&kibibyte) => {
                Ok(Self(kibibyte))
            }
            _ => Err(anyhow!(
                "{} is not in {}..={}",
                Byte::from_bytes(byte).get_appropriate_unit(true),
                Self::MIN,
                Self::MAX
            )),
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

    #[test]
    fn file_name_shell() {
        assert_eq!(Shell::Bash.file_name("abcrypt"), "abcrypt.bash");
        assert_eq!(Shell::Elvish.file_name("abcrypt"), "abcrypt.elv");
        assert_eq!(Shell::Fish.file_name("abcrypt"), "abcrypt.fish");
        assert_eq!(Shell::Nushell.file_name("abcrypt"), "abcrypt.nu");
        assert_eq!(Shell::PowerShell.file_name("abcrypt"), "_abcrypt.ps1");
        assert_eq!(Shell::Zsh.file_name("abcrypt"), "_abcrypt");
    }

    #[test]
    fn default_memory_size() {
        assert_eq!(MemorySize::default(), MemorySize(Params::DEFAULT_M_COST));
    }

    #[test]
    fn deref_memory_size() {
        assert_eq!(*MemorySize::MIN, Params::MIN_M_COST);
        assert_eq!(*MemorySize::default(), Params::DEFAULT_M_COST);
        assert_eq!(*MemorySize::MAX, Params::MAX_M_COST);
    }

    #[test]
    fn display_memory_size() {
        assert_eq!(format!("{}", MemorySize::MIN), "8.00 KiB");
        assert_eq!(format!("{}", MemorySize::default()), "19.00 MiB");
        assert_eq!(format!("{}", MemorySize::MAX), "256.00 GiB");
    }

    #[test]
    fn from_str_memory_size() {
        assert_eq!(
            MemorySize::from_str("19922944 B").unwrap(),
            MemorySize::default()
        );
        assert_eq!(
            MemorySize::from_str("19922944").unwrap(),
            MemorySize::default()
        );
        assert_eq!(
            MemorySize::from_str("19456 KiB").unwrap(),
            MemorySize::default()
        );
        assert_eq!(
            MemorySize::from_str("19.00 MiB").unwrap(),
            MemorySize::default()
        );
        assert_eq!(
            MemorySize::from_str("19MiB").unwrap(),
            MemorySize::default()
        );

        assert_eq!(MemorySize::from_str("128 kB").unwrap(), MemorySize(125));
        assert_eq!(MemorySize::from_str("256kB").unwrap(), MemorySize(250));

        assert_eq!(MemorySize::from_str("8 KiB").unwrap(), MemorySize::MIN);
        assert_eq!(
            MemorySize::from_str("268435455 KiB").unwrap(),
            MemorySize::MAX
        );
    }

    #[test]
    fn from_str_memory_size_with_invalid_unit() {
        use byte_unit::ByteError;

        assert!(matches!(
            MemorySize::from_str("19922944 A")
                .unwrap_err()
                .downcast_ref::<ByteError>()
                .unwrap(),
            ByteError::UnitIncorrect(_)
        ));
        assert!(matches!(
            MemorySize::from_str("19.00LiB")
                .unwrap_err()
                .downcast_ref::<ByteError>()
                .unwrap(),
            ByteError::UnitIncorrect(_)
        ));
    }

    #[test]
    fn from_str_memory_size_with_nan() {
        use byte_unit::ByteError;

        assert!(matches!(
            MemorySize::from_str("n B")
                .unwrap_err()
                .downcast_ref::<ByteError>()
                .unwrap(),
            ByteError::ValueIncorrect(_)
        ));
        assert!(matches!(
            MemorySize::from_str("n")
                .unwrap_err()
                .downcast_ref::<ByteError>()
                .unwrap(),
            ByteError::ValueIncorrect(_)
        ));
        assert!(matches!(
            MemorySize::from_str("nKiB")
                .unwrap_err()
                .downcast_ref::<ByteError>()
                .unwrap(),
            ByteError::ValueIncorrect(_)
        ));
    }

    #[test]
    fn from_str_memory_size_if_out_of_range() {
        assert!(MemorySize::from_str("7 KiB").is_err());
        assert_eq!(MemorySize::from_str("8 KiB").unwrap(), MemorySize::MIN);
        assert_eq!(
            MemorySize::from_str("268435455 KiB").unwrap(),
            MemorySize::MAX
        );
        assert!(MemorySize::from_str("268435456 KiB").is_err());
    }
}
