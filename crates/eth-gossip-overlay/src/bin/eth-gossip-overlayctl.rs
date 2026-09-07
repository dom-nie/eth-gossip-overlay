//! Operator CLI for the sidecar's admin socket (§11, D31).
//!
//! One request per run over a connection of its own: connect, write a JSON line, read the
//! answer, print it and exit. The exit code is what configuration management reads, so it says
//! whether the command took effect and never merely whether the process ran.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use eth_gossip_overlay::admin::{Host, Peer, Request, Response, Status};
use overlay_core::protocol::features;

/// Where the sidecar puts the socket unless `admin_socket` in `config.yaml` moves it
/// (Appendix A). A host that moved it passes `--socket`.
const DEFAULT_SOCKET: &str = "/run/eth-gossip-overlay/admin.sock";

/// The sidecar answered, and the answer says the command did not take effect.
const DAEMON_ERROR: u8 = 1;

/// There was nothing to talk to: no socket, or no permission to open it.
const NO_SOCKET: u8 = 2;

/// Talk to a running eth-gossip-overlay sidecar over its local admin socket.
#[derive(Parser)]
#[command(version, subcommand_required = true, arg_required_else_help = true)]
struct Cli {
    /// The sidecar's admin socket.
    #[arg(long, default_value = DEFAULT_SOCKET, global = true)]
    socket: PathBuf,

    /// Print the sidecar's answer as it came, one JSON object, for jq and scripts.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Turn the inject kill switch on or off, or ask what it is.
    ///
    /// With inject off the sidecar still receives, forwards and reports, and publishes nothing
    /// into the local beacon node. It takes effect on the next message, without a restart.
    Inject {
        /// What to do with the kill switch.
        action: InjectAction,
    },
    /// Print what the sidecar is doing: the kill switch, the beacon node and every live peer.
    ///
    /// The peer table is where a rolling upgrade is read off: each peer's software version and
    /// the feature bits the pair settled on.
    Status,
    /// Print the roster the sidecar is using, or make it read the files again.
    Roster {
        #[command(subcommand)]
        action: Option<RosterAction>,
    },
}

/// What a `roster` command does.
#[derive(Subcommand)]
enum RosterAction {
    /// Re-read config.yaml and roster.yaml, exactly as SIGHUP does.
    ///
    /// A manual reload applies whatever the files say, a roster that halves the fleet
    /// included, which is what the automatic reload refuses and a human confirms here.
    Reload,
}

/// What an `inject` command does to the flag.
#[derive(Clone, Copy, ValueEnum)]
enum InjectAction {
    /// Publish into the beacon node again.
    On,
    /// Stop publishing into the beacon node.
    Off,
    /// Print the flag without changing it.
    Status,
}

impl InjectAction {
    fn value(self) -> Option<bool> {
        match self {
            Self::On => Some(true),
            Self::Off => Some(false),
            Self::Status => None,
        }
    }
}

/// Why there is nothing to print.
enum Failure {
    /// The socket is not there, or this user may not open it. On a production host the sidecar
    /// runs under `DynamicUser=`, so `eth-gossip-overlayctl` runs as root (T-046).
    Connect(io::Error),
    /// The sidecar answered something this cannot read.
    Broken(String),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let request = match &cli.command {
        Command::Inject { action } => Request::Inject {
            value: action.value(),
        },
        Command::Status => Request::Status,
        Command::Roster { action: None } => Request::Roster,
        Command::Roster {
            action: Some(RosterAction::Reload),
        } => Request::Reload,
    };
    match ask(&cli.socket, &request) {
        Ok((line, response)) => {
            if cli.json {
                println!("{}", line.trim_end());
            } else {
                render(&response);
            }
            exit_code(&response)
        }
        Err(Failure::Connect(err)) => {
            eprintln!("eth-gossip-overlayctl: {}: {err}", cli.socket.display());
            ExitCode::from(NO_SOCKET)
        }
        Err(Failure::Broken(reason)) => {
            eprintln!("eth-gossip-overlayctl: {reason}");
            ExitCode::from(DAEMON_ERROR)
        }
    }
}

/// One request, the line that came back and what it says. The line itself is what `--json`
/// prints, so a script reads the sidecar's own object rather than a re-serialized one.
fn ask(socket: &Path, request: &Request) -> Result<(String, Response), Failure> {
    let mut stream = UnixStream::connect(socket).map_err(Failure::Connect)?;
    let line = serde_json::to_string(request).map_err(broken)?;
    writeln!(stream, "{line}").map_err(broken)?;
    let mut answer = String::new();
    BufReader::new(&stream)
        .read_line(&mut answer)
        .map_err(broken)?;
    let response = serde_json::from_str(&answer)
        .map_err(|err| Failure::Broken(format!("{err}: {answer:?}")))?;
    Ok((answer, response))
}

fn broken(err: impl std::fmt::Display) -> Failure {
    Failure::Broken(err.to_string())
}

/// What the operator reads. An error the sidecar reported goes to stderr, so a pipeline that
/// reads stdout gets the answer or nothing.
fn render(response: &Response) {
    if let Some(error) = &response.error {
        eprintln!("eth-gossip-overlayctl: {error}");
    }
    if let Some(inject) = response.inject {
        println!("inject {}", if inject { "on" } else { "off" });
    }
    if let Some(status) = &response.status {
        print_status(status);
    }
    if let Some(hosts) = &response.roster {
        let mut rows = vec![row(["hostname", "region", "site", "addr"])];
        rows.extend(hosts.iter().map(host_row));
        print_table(&rows);
    }
    if let Some(report) = &response.reload {
        println!("applied: {}", names(&report.applied));
        println!("restart required: {}", names(&report.restart_required));
        if let Some(error) = &report.error {
            eprintln!("eth-gossip-overlayctl: {error}");
        }
    }
}

/// The head of a status answer, then one row per live peer.
fn print_status(status: &Status) {
    println!(
        "host    {} ({})",
        status.hostname,
        place(&status.region, status.site.as_deref())
    );
    println!("inject  {}", if status.inject { "on" } else { "off" });
    println!("bn      {}", bn_line(status));
    println!();
    let mut rows = vec![row([
        "hostname",
        "region",
        "site",
        "rtt",
        "up",
        "queue_small",
        "queue_large",
        "version",
        "features",
    ])];
    rows.extend(status.peers.iter().map(peer_row));
    print_table(&rows);
}

/// One live peer's row.
fn peer_row(peer: &Peer) -> Vec<String> {
    vec![
        peer.hostname.clone(),
        peer.region.clone(),
        peer.site.clone().unwrap_or_else(|| "-".to_owned()),
        format!("{:.1}ms", peer.rtt_ms),
        age(peer.connected_for_ms),
        format!("{}f/{}b", peer.queue.small_frames, peer.queue.small_bytes),
        format!("{}f/{}b", peer.queue.large_frames, peer.queue.large_bytes),
        peer.software_version.clone(),
        render_features(peer.features),
    ]
}

/// One roster entry's row.
fn host_row(host: &Host) -> Vec<String> {
    vec![
        host.hostname.clone(),
        host.region.clone(),
        host.site.clone().unwrap_or_else(|| "-".to_owned()),
        host.addr.to_string(),
    ]
}

/// The beacon node in one line: whether the link is up, what it is running, whether it trusts
/// the sidecar and how many topics it wants.
fn bn_line(status: &Status) -> String {
    let trusted = match status.bn.trusted {
        Some(true) => "trusted",
        Some(false) => "NOT TRUSTED",
        None => "trust unknown",
    };
    format!(
        "{}  {}  {trusted}  {} subscriptions",
        if status.bn.connected {
            "connected"
        } else {
            "disconnected"
        },
        status.bn.version.as_deref().unwrap_or("version unknown"),
        status.bn.subscriptions,
    )
}

/// The negotiated feature bits as the number and the names of the bits that are set. An
/// unnamed bit stays part of the number: this release does not know what it is.
fn render_features(features: u64) -> String {
    let names: Vec<&str> = features::NAMES
        .iter()
        .filter(|(_, bit)| features & bit == *bit)
        .map(|(name, _)| *name)
        .collect();
    if names.is_empty() {
        format!("0x{features:x}")
    } else {
        format!("0x{features:x} ({})", names.join(", "))
    }
}

/// A region and an optional site, as metrics label them.
fn place(region: &str, site: Option<&str>) -> String {
    match site {
        Some(site) => format!("{region}/{site}"),
        None => region.to_owned(),
    }
}

/// How long a peer has been up, in the units an operator compares against a slot.
fn age(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m{:02}s", seconds / 60, seconds % 60),
        _ => format!("{}h{:02}m", seconds / 3600, (seconds % 3600) / 60),
    }
}

/// One row of a table.
fn row<const N: usize>(cells: [&str; N]) -> Vec<String> {
    cells.iter().map(|cell| (*cell).to_owned()).collect()
}

/// A table whose columns are as wide as their widest cell. The first row is the header.
fn print_table(rows: &[Vec<String>]) {
    let mut widths = vec![0; rows.first().map_or(0, Vec::len)];
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
}

/// A report's key list as one line.
fn names(keys: &[String]) -> String {
    if keys.is_empty() {
        "none".to_owned()
    } else {
        keys.join(", ")
    }
}

/// 0 when the command took effect, 1 when the sidecar says it did not. A reload that ran and
/// kept the previous values is one of those: the sidecar answered, and what the operator pushed
/// is not in force.
fn exit_code(response: &Response) -> ExitCode {
    let reload_failed = response
        .reload
        .as_ref()
        .is_some_and(|report| report.error.is_some());
    if response.ok && !reload_failed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(DAEMON_ERROR)
    }
}
