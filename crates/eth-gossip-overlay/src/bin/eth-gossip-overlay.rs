//! The sidecar. Argument parsing and the one line a fatal error prints; every subcommand's work
//! lives in the library, so this file stays short enough to read in one go.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use eth_gossip_overlay::version::VERSION;
use eth_gossip_overlay::{app, lifecycle, logging};
use overlay_bn::node_key::NodeKey;
use overlay_core::config::Config;
use overlay_core::identity::create_secret_file;

#[derive(Parser)]
#[command(version = VERSION.as_str(), about)]
struct Cli {
    /// What to do. With no subcommand the sidecar runs.
    #[command(subcommand)]
    command: Option<Command>,

    /// The sidecar's config.yaml.
    #[arg(
        long,
        global = true,
        default_value = "/etc/eth-gossip-overlay/config.yaml"
    )]
    config: PathBuf,

    /// Panic in a spawned task as soon as the wiring is up. Hidden because it exists for one
    /// test: that a panicking task takes the whole process down. A flag rather than a
    /// `cfg(test)` hook, so that test drives the shipped binary and not a build that differs.
    #[arg(long, global = true, hide = true)]
    test_panic: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Run the sidecar, which is what happens with no subcommand at all.
    Run,
    /// Print this host's libp2p peer id, creating the node key on first use.
    ///
    /// Reads only bn.node_key_file from the config; no seed or roster is needed, so it works
    /// on a host that has neither yet.
    PeerId,
    /// Check that the sidecar would start with these files, without starting it.
    ///
    /// Parses the config and roster, resolves this host, loads the seed and derives its TLS
    /// key, loads or creates the node key, and prints the identity and the memory budget a
    /// start would run under.
    CheckConfig,
    /// Create a new fleet seed from the OS random number generator.
    ///
    /// Run once per fleet and copy the file to every host over a secure channel. Refuses to
    /// overwrite an existing file.
    GenSeed {
        /// Where to write the seed, mode 0600.
        #[arg(long, default_value = "/etc/eth-gossip-overlay/seed")]
        out: PathBuf,
    },
    /// Look at what NIC queue steering would do to this host.
    Steering {
        /// Which part of it.
        #[command(subcommand)]
        command: SteeringCommand,
    },
}

#[derive(Subcommand)]
enum SteeringCommand {
    /// Print the changes `overlay.io_thread.steering` would make to this host's NIC, and make
    /// none of them.
    ///
    /// The way to see what `auto` decides about a card before a start acts on it. Reads the
    /// card with `ethtool`, so it needs `ethtool` on the path but no privileges.
    Plan,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("eth-gossip-overlay: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            // Before the subscriber exists, because a configuration that does not parse is the
            // one failure that has nowhere else to be reported.
            let cfg = Config::load(&cli.config)?;
            let log = Arc::new(logging::init(&cfg.log));
            lifecycle::exit_on_panic();
            let served =
                lifecycle::run_to_completion(app::serve(cli.config, cfg, log, cli.test_panic))?;
            served?;
        }
        Command::PeerId => {
            let key = NodeKey::load_or_create(&Config::load(&cli.config)?.bn.node_key_file)?;
            println!("{}", key.peer_id());
        }
        Command::CheckConfig => print!("{}", app::check_config(&cli.config)?),
        Command::GenSeed { out } => {
            create_secret_file(&out)?;
        }
        Command::Steering {
            command: SteeringCommand::Plan,
        } => print!("{}", app::steering_plan(&cli.config)?),
    }
    Ok(())
}
