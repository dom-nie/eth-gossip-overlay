//! The sidecar. Argument parsing and the fatal-error line; every subcommand's work lives in
//! the library, so this file stays short enough to read in one go.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fleet_overlay::app;
use overlay_bn::node_key::NodeKey;
use overlay_core::config::Config;
use overlay_core::identity::create_secret_file;

#[derive(Parser)]
#[command(
    version,
    about,
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this host's libp2p peer id, creating the node key on first use.
    ///
    /// Reads only bn.node_key_file from the config; no seed or roster is needed, so it works
    /// on a host that has neither yet.
    PeerId {
        /// The sidecar's config.yaml.
        #[arg(long, default_value = "/etc/fleet-overlay/config.yaml")]
        config: PathBuf,
    },
    /// Check that the sidecar would start with these files, without starting it.
    ///
    /// Parses the config and roster, resolves this host, loads the seed and derives its TLS
    /// key, loads or creates the node key, and prints the identity and the memory budget a
    /// start would run under.
    CheckConfig {
        /// The sidecar's config.yaml.
        #[arg(long, default_value = "/etc/fleet-overlay/config.yaml")]
        config: PathBuf,
    },
    /// Create a new fleet seed from the OS random number generator.
    ///
    /// Run once per fleet and copy the file to every host over a secure channel. Refuses to
    /// overwrite an existing file.
    GenSeed {
        /// Where to write the seed, mode 0600.
        #[arg(long, default_value = "/etc/fleet-overlay/seed")]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("fleet-overlay: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::PeerId { config } => {
            let config = Config::load(&config)?;
            let key = NodeKey::load_or_create(&config.bn.node_key_file)?;
            println!("{}", key.peer_id());
        }
        Command::CheckConfig { config } => {
            print!("{}", app::check_config(&config)?);
        }
        Command::GenSeed { out } => {
            create_secret_file(&out)?;
        }
    }
    Ok(())
}
