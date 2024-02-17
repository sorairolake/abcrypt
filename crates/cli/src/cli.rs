// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Write},
    ops::Deref,
    path::PathBuf,
    str::FromStr,
};

use abcrypt::argon2::Params;
use anyhow::anyhow;
use byte_unit::{Byte, Unit};
use clap::{
    builder::{TypedValueParser, ValueParserFactory},
    value_parser, ArgGroup, Args, CommandFactory, Parser, Subcommand, ValueEnum, ValueHint,
};
use clap_complete::Generator;

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    '\n',
    "Copyright (C) 2022-2024 Shun Sakai\n",
    '\n',
    "This program is distributed under the terms of the GNU General Public License\n",
    "v3.0 or later.\n",
    '\n',
    "This is free software: you are free to change and redistribute it. There is NO\n",
    "WARRANTY, to the extent permitted by law.\n",
    '\n',
    "Report bugs to <https://github.com/sorairolake/abcrypt/issues>."
);

const AFTER_LONG_HELP: &str = "See `abcrypt(1)` for more details.";

const ENCRYPT_AFTER_LONG_HELP: &str = concat!(
    "By default, the result will be write to stdout.\n",
    '\n',
    "See `abcrypt-encrypt(1)` for more details."
);

const DECRYPT_AFTER_LONG_HELP: &str = concat!(
    "By default, the result will be write to stdout.\n",
    '\n',
    "See `abcrypt-decrypt(1)` for more details."
);

const INFORMATION_AFTER_LONG_HELP: &str = concat!(
    "The result will be write to stdout.\n",
    '\n',
    "See `abcrypt-information(1)` for more details."
);

#[derive(Debug, Parser)]
#[command(
    name("abcrypt"),
    version,
    long_version(LONG_VERSION),
    about,
    max_term_width(100),
    propagate_version(true),
    after_long_help(AFTER_LONG_HELP),
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
    #[command(
        after_long_help(ENCRYPT_AFTER_LONG_HELP),
        visible_alias("enc"),
        visible_alias("e")
    )]
    Encrypt(Encrypt),

    /// Decrypt files.
    #[command(
        after_long_help(DECRYPT_AFTER_LONG_HELP),
        visible_alias("dec"),
        visible_alias("d")
    )]
    Decrypt(Decrypt),

    /// Provides information about the encryption parameters.
    #[command(
        after_long_help(INFORMATION_AFTER_LONG_HELP),
        visible_alias("info"),
        visible_alias("i")
    )]
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
    pub memory_cost: MemoryCost,

    /// Set the number of iterations.
    #[arg(short, long, default_value_t, value_name("NUM"))]
    pub time_cost: TimeCost,

    /// Set the degree of parallelism.
    #[arg(short, long, default_value_t, value_name("NUM"))]
    pub parallelism: Parallelism,

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

    #[allow(clippy::enum_variant_names)]
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
pub struct MemoryCost(u32);

impl MemoryCost {
    /// Minimum number of 1 KiB memory blocks.
    const MIN: Self = Self(Params::MIN_M_COST);

    /// Maximum number of 1 KiB memory blocks.
    const MAX: Self = Self(Params::MAX_M_COST);
}

impl Default for MemoryCost {
    fn default() -> Self {
        Self(Params::DEFAULT_M_COST)
    }
}

impl Deref for MemoryCost {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MemoryCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let byte =
            Byte::from(u64::from(self.0) * Byte::KIBIBYTE.as_u64()).get_adjusted_unit(Unit::KiB);
        write!(f, "{byte:.0}")
    }
}

impl FromStr for MemoryCost {
    type Err = anyhow::Error;

    fn from_str(byte: &str) -> anyhow::Result<Self> {
        let byte = Byte::from_str(byte)
            .map(u64::from)
            .map_err(anyhow::Error::from)?;
        match u32::try_from(byte / Byte::KIBIBYTE.as_u64()) {
            Ok(kibibyte) if (Params::MIN_M_COST..=Params::MAX_M_COST).contains(&kibibyte) => {
                Ok(Self(kibibyte))
            }
            _ => Err(anyhow!(
                "{:.0} is not in {}..={}",
                Byte::from(byte).get_adjusted_unit(Unit::KiB),
                Self::MIN,
                Self::MAX
            )),
        }
    }
}

/// Number of iterations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeCost(u32);

impl Default for TimeCost {
    fn default() -> Self {
        Self(Params::DEFAULT_T_COST)
    }
}

impl Deref for TimeCost {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for TimeCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ValueParserFactory for TimeCost {
    type Parser = TimeCostValueParser;

    fn value_parser() -> Self::Parser {
        TimeCostValueParser
    }
}

/// Parse [`TimeCost`].
#[derive(Clone, Copy, Debug)]
pub struct TimeCostValueParser;

impl TypedValueParser for TimeCostValueParser {
    type Value = TimeCost;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let inner =
            value_parser!(u32).range(i64::from(Params::MIN_T_COST)..=Params::MAX_T_COST.into());
        inner.parse_ref(cmd, arg, value).map(TimeCost)
    }
}

/// Degree of parallelism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parallelism(u32);

impl Default for Parallelism {
    fn default() -> Self {
        Self(Params::DEFAULT_P_COST)
    }
}

impl Deref for Parallelism {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Parallelism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ValueParserFactory for Parallelism {
    type Parser = ParallelismValueParser;

    fn value_parser() -> Self::Parser {
        ParallelismValueParser
    }
}

/// Parse [`Parallelism`].
#[derive(Clone, Copy, Debug)]
pub struct ParallelismValueParser;

impl TypedValueParser for ParallelismValueParser {
    type Value = Parallelism;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let inner =
            value_parser!(u32).range(i64::from(Params::MIN_P_COST)..=Params::MAX_P_COST.into());
        inner.parse_ref(cmd, arg, value).map(Parallelism)
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
    fn default_memory_cost() {
        assert_eq!(MemoryCost::default(), MemoryCost(Params::DEFAULT_M_COST));
    }

    #[test]
    fn deref_memory_cost() {
        assert_eq!(*MemoryCost::MIN, Params::MIN_M_COST);
        assert_eq!(*MemoryCost::default(), Params::DEFAULT_M_COST);
        assert_eq!(*MemoryCost::MAX, Params::MAX_M_COST);
    }

    #[test]
    fn display_memory_cost() {
        assert_eq!(format!("{}", MemoryCost::MIN), "8 KiB");
        assert_eq!(format!("{}", MemoryCost::default()), "19456 KiB");
        assert_eq!(format!("{}", MemoryCost::MAX), "4294967295 KiB");
    }

    #[test]
    fn from_str_memory_cost() {
        assert_eq!(
            MemoryCost::from_str("19922944 B").unwrap(),
            MemoryCost::default()
        );
        assert_eq!(
            MemoryCost::from_str("19922944").unwrap(),
            MemoryCost::default()
        );
        assert_eq!(
            MemoryCost::from_str("19456 KiB").unwrap(),
            MemoryCost::default()
        );
        assert_eq!(
            MemoryCost::from_str("19.00 MiB").unwrap(),
            MemoryCost::default()
        );
        assert_eq!(
            MemoryCost::from_str("19MiB").unwrap(),
            MemoryCost::default()
        );

        assert_eq!(MemoryCost::from_str("128 kB").unwrap(), MemoryCost(125));
        assert_eq!(MemoryCost::from_str("256kB").unwrap(), MemoryCost(250));

        assert_eq!(MemoryCost::from_str("8 KiB").unwrap(), MemoryCost::MIN);
        assert_eq!(
            MemoryCost::from_str("4294967295 KiB").unwrap(),
            MemoryCost::MAX
        );
    }

    #[test]
    fn from_str_memory_cost_with_invalid_unit() {
        use byte_unit::ParseError;

        assert!(matches!(
            MemoryCost::from_str("19922944 A")
                .unwrap_err()
                .downcast_ref::<ParseError>()
                .unwrap(),
            ParseError::Unit(_)
        ));
        assert!(matches!(
            MemoryCost::from_str("19.00LiB")
                .unwrap_err()
                .downcast_ref::<ParseError>()
                .unwrap(),
            ParseError::Unit(_)
        ));
    }

    #[test]
    fn from_str_memory_cost_with_nan() {
        use byte_unit::ParseError;

        assert!(matches!(
            MemoryCost::from_str("n B")
                .unwrap_err()
                .downcast_ref::<ParseError>()
                .unwrap(),
            ParseError::Value(_)
        ));
        assert!(matches!(
            MemoryCost::from_str("n")
                .unwrap_err()
                .downcast_ref::<ParseError>()
                .unwrap(),
            ParseError::Value(_)
        ));
        assert!(matches!(
            MemoryCost::from_str("nKiB")
                .unwrap_err()
                .downcast_ref::<ParseError>()
                .unwrap(),
            ParseError::Value(_)
        ));
    }

    #[test]
    fn from_str_memory_cost_if_out_of_range() {
        assert!(MemoryCost::from_str("7 KiB").is_err());
        assert_eq!(MemoryCost::from_str("8 KiB").unwrap(), MemoryCost::MIN);
        assert_eq!(
            MemoryCost::from_str("4294967295 KiB").unwrap(),
            MemoryCost::MAX
        );
        assert!(MemoryCost::from_str("4294967296 KiB").is_err());
    }

    impl TimeCost {
        /// Minimum number of passes.
        const MIN: Self = Self(Params::MIN_T_COST);

        /// Maximum number of passes.
        const MAX: Self = Self(Params::MAX_T_COST);
    }

    #[test]
    fn default_time_cost() {
        assert_eq!(TimeCost::default(), TimeCost(Params::DEFAULT_T_COST));
    }

    #[test]
    fn deref_time_cost() {
        assert_eq!(*TimeCost::MIN, Params::MIN_T_COST);
        assert_eq!(*TimeCost::default(), Params::DEFAULT_T_COST);
        assert_eq!(*TimeCost::MAX, Params::MAX_T_COST);
    }

    #[test]
    fn display_time_cost() {
        assert_eq!(format!("{}", TimeCost::MIN), "1");
        assert_eq!(format!("{}", TimeCost::default()), "2");
        assert_eq!(format!("{}", TimeCost::MAX), "4294967295");
    }

    #[test]
    fn value_parser_time_cost() {
        #[derive(Debug, Eq, Parser, PartialEq)]
        pub struct Opt {
            #[arg(short('t'), long, default_value_t, value_name("NUM"))]
            pub time_cost: TimeCost,
        }

        assert_eq!(
            Opt::try_parse_from(["test", "-t1"]).unwrap(),
            Opt {
                time_cost: TimeCost::MIN
            }
        );
        assert_eq!(
            Opt::try_parse_from(["test", "-t4294967295"]).unwrap(),
            Opt {
                time_cost: TimeCost::MAX
            }
        );

        assert_eq!(
            Opt::try_parse_from(["test"]).unwrap(),
            Opt {
                time_cost: TimeCost::default()
            }
        );

        assert!(Opt::try_parse_from(["test", "-tn"])
            .unwrap_err()
            .to_string()
            .contains("invalid digit found in string"));

        assert!(Opt::try_parse_from(["test", "-t0"])
            .unwrap_err()
            .to_string()
            .contains("0 is not in 1..=4294967295"));
        assert!(Opt::try_parse_from(["test", "-t4294967296"])
            .unwrap_err()
            .to_string()
            .contains("4294967296 is not in 1..=4294967295"));
    }

    #[test]
    fn parse_ref_time_cost_value_parser() {
        assert_eq!(TimeCost::default(), TimeCost(Params::DEFAULT_T_COST));

        assert_eq!(
            TypedValueParser::parse_ref(
                &TimeCostValueParser,
                &clap::Command::new("test"),
                None,
                OsStr::new("1")
            )
            .unwrap(),
            TimeCost::MIN
        );
        assert_eq!(
            TypedValueParser::parse_ref(
                &TimeCostValueParser,
                &clap::Command::new("test"),
                None,
                OsStr::new("4294967295")
            )
            .unwrap(),
            TimeCost::MAX
        );

        assert!(TypedValueParser::parse_ref(
            &TimeCostValueParser,
            &clap::Command::new("test"),
            None,
            OsStr::new("n")
        )
        .unwrap_err()
        .to_string()
        .contains("invalid digit found in string"));

        assert!(TypedValueParser::parse_ref(
            &TimeCostValueParser,
            &clap::Command::new("test"),
            None,
            OsStr::new("0")
        )
        .unwrap_err()
        .to_string()
        .contains("0 is not in 1..=4294967295"));
        assert!(TypedValueParser::parse_ref(
            &TimeCostValueParser,
            &clap::Command::new("test"),
            None,
            OsStr::new("4294967296")
        )
        .unwrap_err()
        .to_string()
        .contains("4294967296 is not in 1..=4294967295"));
    }

    impl Parallelism {
        /// Minimum number of threads.
        const MIN: Self = Self(Params::MIN_P_COST);

        /// Maximum number of threads.
        const MAX: Self = Self(Params::MAX_P_COST);
    }

    #[test]
    fn default_parallelism() {
        assert_eq!(Parallelism::default(), Parallelism(Params::DEFAULT_P_COST));
    }

    #[test]
    fn deref_parallelism() {
        assert_eq!(*Parallelism::MIN, Params::MIN_P_COST);
        assert_eq!(*Parallelism::default(), Params::DEFAULT_P_COST);
        assert_eq!(*Parallelism::MAX, Params::MAX_P_COST);
    }

    #[test]
    fn display_parallelism() {
        assert_eq!(format!("{}", Parallelism::MIN), "1");
        assert_eq!(format!("{}", Parallelism::default()), "1");
        assert_eq!(format!("{}", Parallelism::MAX), "16777215");
    }

    #[test]
    fn value_parser_parallelism() {
        #[derive(Debug, Eq, Parser, PartialEq)]
        pub struct Opt {
            #[arg(short, long, default_value_t, value_name("NUM"))]
            pub parallelism: Parallelism,
        }

        assert_eq!(
            Opt::try_parse_from(["test", "-p1"]).unwrap(),
            Opt {
                parallelism: Parallelism::MIN
            }
        );
        assert_eq!(
            Opt::try_parse_from(["test", "-p16777215"]).unwrap(),
            Opt {
                parallelism: Parallelism::MAX
            }
        );

        assert_eq!(
            Opt::try_parse_from(["test"]).unwrap(),
            Opt {
                parallelism: Parallelism::default()
            }
        );

        assert!(Opt::try_parse_from(["test", "-pn"])
            .unwrap_err()
            .to_string()
            .contains("invalid digit found in string"));

        assert!(Opt::try_parse_from(["test", "-p0"])
            .unwrap_err()
            .to_string()
            .contains("0 is not in 1..=16777215"));
        assert!(Opt::try_parse_from(["test", "-p16777216"])
            .unwrap_err()
            .to_string()
            .contains("16777216 is not in 1..=16777215"));
    }

    #[test]
    fn parse_ref_parallelism_value_parser() {
        assert_eq!(
            TypedValueParser::parse_ref(
                &ParallelismValueParser,
                &clap::Command::new("test"),
                None,
                OsStr::new("1")
            )
            .unwrap(),
            Parallelism::MIN
        );
        assert_eq!(
            TypedValueParser::parse_ref(
                &ParallelismValueParser,
                &clap::Command::new("test"),
                None,
                OsStr::new("16777215")
            )
            .unwrap(),
            Parallelism::MAX
        );

        assert!(TypedValueParser::parse_ref(
            &ParallelismValueParser,
            &clap::Command::new("test"),
            None,
            OsStr::new("n")
        )
        .unwrap_err()
        .to_string()
        .contains("invalid digit found in string"));

        assert!(TypedValueParser::parse_ref(
            &ParallelismValueParser,
            &clap::Command::new("test"),
            None,
            OsStr::new("0")
        )
        .unwrap_err()
        .to_string()
        .contains("0 is not in 1..=16777215"));
        assert!(TypedValueParser::parse_ref(
            &ParallelismValueParser,
            &clap::Command::new("test"),
            None,
            OsStr::new("16777216")
        )
        .unwrap_err()
        .to_string()
        .contains("16777216 is not in 1..=16777215"));
    }
}
