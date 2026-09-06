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
use fleet_overlay::admin::{Request, Response};

/// Where the sidecar puts the socket unless `admin_socket` in `config.yaml` moves it
/// (Appendix A). A host that moved it passes `--socket`.
const DEFAULT_SOCKET: &str = "/run/fleet-overlay/admin.sock";

/// The sidecar answered, and the answer says the command did not take effect.
const DAEMON_ERROR: u8 = 1;

/// There was nothing to talk to: no socket, or no permission to open it.
const NO_SOCKET: u8 = 2;

#[derive(Parser)]
#[command(
    version,
    about,
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// The sidecar's admin socket.
    #[arg(long, default_value = DEFAULT_SOCKET, global = true)]
    socket: PathBuf,

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
    /// runs under `DynamicUser=`, so `fleet-overlayctl` runs as root (T-046).
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
    };
    match ask(&cli.socket, &request) {
        Ok(response) => {
            render(&response);
            exit_code(&response)
        }
        Err(Failure::Connect(err)) => {
            eprintln!("fleet-overlayctl: {}: {err}", cli.socket.display());
            ExitCode::from(NO_SOCKET)
        }
        Err(Failure::Broken(reason)) => {
            eprintln!("fleet-overlayctl: {reason}");
            ExitCode::from(DAEMON_ERROR)
        }
    }
}

/// One request and its answer.
fn ask(socket: &Path, request: &Request) -> Result<Response, Failure> {
    let mut stream = UnixStream::connect(socket).map_err(Failure::Connect)?;
    let line = serde_json::to_string(request).map_err(broken)?;
    writeln!(stream, "{line}").map_err(broken)?;
    let mut answer = String::new();
    BufReader::new(&stream)
        .read_line(&mut answer)
        .map_err(broken)?;
    serde_json::from_str(&answer).map_err(|err| Failure::Broken(format!("{err}: {answer:?}")))
}

fn broken(err: impl std::fmt::Display) -> Failure {
    Failure::Broken(err.to_string())
}

/// What the operator reads. An error the sidecar reported goes to stderr, so a pipeline that
/// reads stdout gets the answer or nothing.
fn render(response: &Response) {
    if let Some(error) = &response.error {
        eprintln!("fleet-overlayctl: {error}");
    }
    if let Some(inject) = response.inject {
        println!("inject {}", if inject { "on" } else { "off" });
    }
}

/// 0 when the command took effect, 1 when the sidecar says it did not.
fn exit_code(response: &Response) -> ExitCode {
    if response.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(DAEMON_ERROR)
    }
}
