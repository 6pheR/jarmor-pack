use clap::{Parser, Subcommand, Args};

/// Command-line interface for jarmor-pack
#[derive(Parser)]
#[command(name = "jarmor-pack")]
#[command(version = "1.0")]
#[command(about = "Pack .jar files securely into .enc format")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands
#[derive(Subcommand)]
pub enum Command {
    /// Encrypt a .jar file into a .enc archive
    Pack(PackArgs),

    /// Display supported encryption algorithms
    ListAlgos,
}

/// Arguments for the `pack` subcommand
#[derive(Args)]
pub struct PackArgs {
    /// Path to the input .jar file
    #[arg(short, long)]
    pub input: String,

    /// Path to the output .enc file
    #[arg(short, long)]
    pub output: String,

    /// Secret key or passphrase
    #[arg(short, long)]
    pub key: String,

    /// Encryption algorithm (default: aes256gcm)
    #[arg(short, long, default_value = "aes256gcm")]
    pub algo: String,
}

/// Parse and return the selected command
pub fn parse_args() -> Command {
    Cli::parse().command
}
