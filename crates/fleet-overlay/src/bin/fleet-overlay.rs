//! The sidecar. The `run` subcommand and the wiring arrive with T-045; until then the binary
//! only serves the two identity commands an operator needs before the first start.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use overlay_bn::node_key::NodeKey;
use overlay_core::config::Config;

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
    }
    Ok(())
}
