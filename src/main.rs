//! jarmor-pack: CLI tool to encrypt .jar files into .enc format

mod crypto;
mod cli;

use cli::{Command, PackArgs};
use crypto::{encrypt_file, list_algorithms};
use std::process;

fn main() {
    // Parse CLI arguments
    let command = cli::parse_args();

    match command {
        Command::Pack(PackArgs { input, output, key, algo }) => {
            // Run encryption and handle potential error
            if let Err(e) = encrypt_file(&input, &output, &key, &algo) {
                eprintln!("❌ Error: {}", e);
                process::exit(1);
            } else {
                println!("✅ Packed successfully to {}", output);
            }
        }

        Command::ListAlgos => {
            // Show supported encryption algorithms
            list_algorithms();
        }
    }
}
