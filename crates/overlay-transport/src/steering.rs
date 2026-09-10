//! Steering the overlay's UDP traffic to a NIC queue of its own (§11).
//!
//! The NIC is shared with the beacon node's public gossip, so the overlay gets a queue rather
//! than an interface. An ntuple flow rule puts UDP 7788 on one receive queue where the card can
//! do it, receive flow steering does the same job in the kernel where it cannot, and that
//! queue's interrupt and NAPI thread go on the core `io_thread.pin_cpu` reserved. Signature
//! verification on the beacon node's cores then never contends with fan-out.
//!
//! All of it needs privileges and none of it is portable, so the work is split: [`plan`] is
//! arithmetic over what a card reported and says what would be done, and applying is the thin
//! part that does it. `eth-gossip-overlay steering plan` prints the plan without applying it,
//! which is how an operator sees what `auto` would do to a host before turning it on.
//!
//! It is off in the shipped defaults (D30) and nothing here runs until an operator sets
//! `io_thread.steering`.

use std::fmt;
use std::io;
use std::path::Path;
use std::process::Command;

use overlay_core::config::{IoThread, Steering};

/// The flow table receive flow steering hashes into, which `deploy/sysctl` sets system-wide.
/// Each queue gets an equal share of it, which is what `rps_flow_cnt` counts.
const RPS_SOCK_FLOW_ENTRIES: u32 = 32_768;

/// Receive interrupt coalescing for the overlay's queue alone, in microseconds (§11). Low
/// enough that a chunk does not wait on a timer, and only ever set on one queue, so the beacon
/// node's traffic keeps the card's defaults.
const COALESCE_RX_USECS: u32 = 8;

/// What a NIC can be asked to do, read once at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NicCaps {
    /// The interface carrying the default route, which is the one interface §11 gives a host.
    pub iface: String,
    /// How many receive queues the card is running with. The overlay takes the last of them.
    pub rx_queues: u32,
    /// Whether the card can steer a flow to a queue itself, which is `ethtool -k`'s
    /// `ntuple-filters`.
    pub ntuple: bool,
    /// Whether coalescing can be set for one queue rather than for the whole card.
    pub per_queue_coalesce: bool,
}

/// One change to a NIC, in the order a plan makes them.
///
/// Every variant names the interface, because the plan an operator reads has to say what it
/// would touch without the reader holding the [`NicCaps`] it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A flow rule steering one address family's UDP traffic on `port` to `queue`.
    NtupleRule {
        /// The interface the rule goes on.
        iface: String,
        /// `udp4` or `udp6`, which is `ethtool -N`'s own word for the family.
        flow_type: &'static str,
        /// The destination port the rule matches, which is where the overlay listens.
        port: u16,
        /// The receive queue the matching packets land on.
        queue: u32,
    },
    /// This queue's share of the receive flow table, for cards with no ntuple support.
    RfsFlowEntries {
        /// The interface whose queue is being sized.
        iface: String,
        /// The receive queue.
        queue: u32,
        /// Flows the queue may track at once.
        entries: u32,
    },
    /// The queue's interrupt on the reserved core.
    IrqAffinity {
        /// The interface whose queue's interrupt is being moved.
        iface: String,
        /// The receive queue.
        queue: u32,
        /// The core `io_thread.pin_cpu` reserved.
        cpu: u32,
    },
    /// NAPI polling in kernel threads rather than in softirq, so the overlay queue's polling is
    /// scheduled onto the reserved core with everything else.
    ThreadedNapi {
        /// The interface. Threaded NAPI is a per-interface setting, not a per-queue one.
        iface: String,
    },
    /// Receive coalescing for the overlay's queue alone.
    PerQueueCoalesce {
        /// The interface.
        iface: String,
        /// The receive queue.
        queue: u32,
        /// How long the card may hold a packet before it raises the interrupt.
        rx_usecs: u32,
    },
}

impl Action {
    /// The word this action goes under in `overlay_steering_applied`. One label per kind rather
    /// than per queue: what an operator wants from the gauge is which halves of the plan took.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NtupleRule { .. } => "ntuple",
            Self::RfsFlowEntries { .. } => "rfs",
            Self::IrqAffinity { .. } => "irq_affinity",
            Self::ThreadedNapi { .. } => "threaded_napi",
            Self::PerQueueCoalesce { .. } => "coalesce",
        }
    }
}

/// One line per action, which is what `eth-gossip-overlay steering plan` prints and what
/// `docs/performance.md` shows for the two kinds of card.
impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NtupleRule {
                iface,
                flow_type,
                port,
                queue,
            } => write!(
                f,
                "ntuple rule: {iface} {flow_type} dst-port {port} to queue {queue}"
            ),
            Self::RfsFlowEntries {
                iface,
                queue,
                entries,
            } => write!(f, "rfs: {iface} queue {queue} tracks {entries} flows"),
            Self::IrqAffinity { iface, queue, cpu } => {
                write!(f, "irq affinity: {iface} queue {queue} to cpu {cpu}")
            }
            Self::ThreadedNapi { iface } => write!(f, "threaded napi: on for {iface}"),
            Self::PerQueueCoalesce {
                iface,
                queue,
                rx_usecs,
            } => write!(
                f,
                "coalesce: {iface} queue {queue} adaptive-rx off, rx-usecs {rx_usecs}"
            ),
        }
    }
}

/// Whether the card can steer a flow to a queue itself, from `ethtool -k`.
///
/// "On" is not the question. Cards that have the filter ship with it off, and `ethtool -K` turns
/// it on; what says a card has no filter at all is the `[fixed]` marker beside an `off`.
fn supports_ntuple(features: &str) -> bool {
    features.lines().any(|line| {
        let Some((key, state)) = line.split_once(':') else {
            return false;
        };
        if !matches!(key.trim(), "ntuple-filters" | "ntuple") {
            return false;
        }
        let state = state.trim();
        state.starts_with("on") || !state.contains("[fixed]")
    })
}

/// How many receive queues the card is running with, from `ethtool -l`.
///
/// The current settings and not the card's maximums, because the queue the overlay takes has to
/// exist now. `Combined` where the card pairs its receive and transmit rings, `RX` where it
/// keeps them apart; `n/a` and `0` are the card saying it has none of that kind.
fn rx_queues(channels: &str) -> Option<u32> {
    let current = channels.split_once("Current hardware settings:")?.1;
    let count = |name: &str| {
        current
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim() == name)
            .and_then(|(_, value)| value.trim().parse::<u32>().ok())
            .filter(|queues| *queues > 0)
    };
    count("Combined").or_else(|| count("RX"))
}

/// The interface carrying the default route, from `/proc/net/route`.
///
/// §11 gives a host one interface and the beacon node already uses it, so there is no interface
/// to configure anywhere: the overlay steers whichever one the packets are coming in on.
fn default_iface(routes: &str) -> Option<String> {
    routes.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let iface = fields.next()?;
        let destination = fields.next()?;
        (destination == "00000000").then(|| iface.to_owned())
    })
}

/// What `cfg` asks for on a card with these capabilities, in the order it should be applied.
///
/// Pure, so the dry run and the startup path compute the same list and an operator who read one
/// gets the other. An empty plan is a complete answer: `steering: off` is the shipped default,
/// and a card asked for a rule it cannot make is told so rather than steered some other way.
pub fn plan(caps: &NicCaps, cfg: &IoThread, port: u16) -> Vec<Action> {
    let Some(queue) = caps.rx_queues.checked_sub(1) else {
        return Vec::new();
    };
    let iface = || caps.iface.clone();
    let mut plan = match (cfg.steering, caps.ntuple) {
        (Steering::Off, _) => return Vec::new(),
        // An operator who named `ntuple` asked for the card to do the steering. A card that
        // cannot is worth an empty plan and a line saying so, not a silent substitution.
        (Steering::Ntuple, false) => return Vec::new(),
        (Steering::Auto | Steering::Ntuple, true) => ["udp4", "udp6"]
            .into_iter()
            .map(|flow_type| Action::NtupleRule {
                iface: iface(),
                flow_type,
                port,
                queue,
            })
            .collect(),
        (Steering::Auto | Steering::Rfs, _) => vec![Action::RfsFlowEntries {
            iface: iface(),
            queue,
            entries: RPS_SOCK_FLOW_ENTRIES / caps.rx_queues,
        }],
    };
    // Steering with no reserved core still gives the overlay a queue to itself, which is worth
    // having; there is just nowhere to put the interrupt.
    if let Some(cpu) = cfg.pin_cpu {
        plan.push(Action::IrqAffinity {
            iface: iface(),
            queue,
            cpu,
        });
        plan.push(Action::ThreadedNapi { iface: iface() });
    }
    if caps.per_queue_coalesce {
        plan.push(Action::PerQueueCoalesce {
            iface: iface(),
            queue,
            rx_usecs: COALESCE_RX_USECS,
        });
    }
    plan
}

/// What this module asks of the host it is running on.
///
/// Behind a trait for the same reason T-092's kernel calls are: no test can arrange a card with
/// no ntuple support, a `/proc/irq` entry that refuses a write, or the privileges any of it
/// needs. [`Host`] is the one implementation that reaches a real NIC.
pub(crate) trait Nic {
    /// `ethtool <args>`, with its own output as the error where it exits non-zero. `ethtool`
    /// rather than the ioctls behind it: the same command an operator runs by hand, so a plan
    /// that failed can be reproduced from the log line that reports it.
    fn ethtool(&self, args: &[&str]) -> io::Result<String>;
    /// The contents of a `/sys` or `/proc` file.
    fn read(&self, path: &Path) -> io::Result<String>;
}

/// The NIC this host is running on.
pub(crate) struct Host;

impl Nic for Host {
    fn ethtool(&self, args: &[&str]) -> io::Result<String> {
        let done = Command::new("ethtool").args(args).output()?;
        if !done.status.success() {
            let said = String::from_utf8_lossy(&done.stderr);
            return Err(io::Error::other(format!(
                "ethtool {}: {}",
                args.join(" "),
                said.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&done.stdout).into_owned())
    }

    fn read(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }
}

/// What the card behind the default route can be asked to do.
///
/// Three `ethtool` runs at startup and never again: the capabilities decide the plan and none of
/// them change under a running process.
pub fn detect() -> io::Result<NicCaps> {
    detect_with(&Host)
}

fn detect_with(nic: &dyn Nic) -> io::Result<NicCaps> {
    let routes = nic.read(Path::new("/proc/net/route"))?;
    let iface = default_iface(&routes)
        .ok_or_else(|| io::Error::other("no default route to name an interface"))?;
    let features = nic.ethtool(&["-k", &iface])?;
    let channels = nic.ethtool(&["-l", &iface])?;
    // A card that answers the per-queue form at all can take a per-queue coalesce setting; one
    // that cannot prints an error and exits non-zero, which is the whole of the question §11
    // asks before it touches coalescing at all.
    let per_queue_coalesce = nic
        .ethtool(&[
            "--per-queue",
            &iface,
            "queue_mask",
            "0x1",
            "--show-coalesce",
        ])
        .is_ok();
    Ok(NicCaps {
        rx_queues: rx_queues(&channels).unwrap_or_default(),
        ntuple: supports_ntuple(&features),
        per_queue_coalesce,
        iface,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use overlay_core::config::{IoThread, Steering};

    use super::*;

    /// A host whose `ethtool` and `/proc` answer whatever the test needs, recording what it was
    /// asked in the order it was asked.
    struct Fake {
        /// `ethtool -k` output.
        features: &'static str,
        /// `ethtool -l` output.
        channels: &'static str,
        /// Whether `ethtool --per-queue` is answered at all.
        per_queue: bool,
        /// The default route table, in `/proc/net/route`'s columns.
        routes: &'static str,
        /// `/proc/interrupts`, which is where a queue's interrupt number comes from.
        interrupts: &'static str,
        /// Every `ethtool` run and every file written, in order.
        calls: Mutex<Vec<String>>,
        /// A call whose text contains this fails. Every failure worth testing is one no host
        /// can be asked for: a card that refuses a rule, a `/proc/irq` entry that will not move.
        fails: Option<&'static str>,
        /// What the `/sys` and `/proc` files hold.
        files: Mutex<BTreeMap<PathBuf, String>>,
    }

    /// A route table with one default route, which is what §11's single-interface host has.
    const ROUTES: &str = concat!(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
        "eth0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n",
        "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
    );

    /// Eight receive interrupts named the way the Intel drivers name them, which is the naming
    /// [`irq_for`] can follow.
    const INTERRUPTS: &str = concat!(
        "           CPU0       CPU1\n",
        " 124:       1000          0  IR-PCI-MSI-524288-edge      eth0-TxRx-0\n",
        " 125:       1000          0  IR-PCI-MSI-524289-edge      eth0-TxRx-1\n",
        " 126:       1000          0  IR-PCI-MSI-524290-edge      eth0-TxRx-2\n",
        " 127:       1000          0  IR-PCI-MSI-524291-edge      eth0-TxRx-3\n",
        " 128:       1000          0  IR-PCI-MSI-524292-edge      eth0-TxRx-4\n",
        " 129:       1000          0  IR-PCI-MSI-524293-edge      eth0-TxRx-5\n",
        " 130:       1000          0  IR-PCI-MSI-524294-edge      eth0-TxRx-6\n",
        " 131:       1000          0  IR-PCI-MSI-524295-edge      eth0-TxRx-7\n",
    );

    impl Default for Fake {
        fn default() -> Self {
            Self {
                features: include_str!("steering/fixtures/mlx5-connectx5-features.txt"),
                channels: include_str!("steering/fixtures/mlx5-connectx5-channels.txt"),
                per_queue: false,
                routes: ROUTES,
                interrupts: INTERRUPTS,
                calls: Mutex::new(Vec::new()),
                fails: None,
                files: Mutex::new(BTreeMap::new()),
            }
        }
    }

    #[allow(clippy::unwrap_used)]
    impl Fake {
        /// Every `ethtool` run and file write, in the order they were made.
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }

        /// Records `call` and refuses it where the test asked for a refusal.
        fn refuse(&self, call: &str) -> io::Result<()> {
            self.calls.lock().unwrap().push(call.to_owned());
            match self.fails {
                Some(needle) if call.contains(needle) => {
                    Err(io::Error::other(format!("device refused {needle}")))
                }
                _ => Ok(()),
            }
        }
    }

    #[allow(clippy::unwrap_used)]
    impl Nic for Fake {
        fn ethtool(&self, args: &[&str]) -> io::Result<String> {
            self.refuse(&format!("ethtool {}", args.join(" ")))?;
            match args.first().copied() {
                Some("-k") => Ok(self.features.to_owned()),
                Some("-l") => Ok(self.channels.to_owned()),
                Some("--per-queue") if !self.per_queue => {
                    Err(io::Error::other("Cannot get device per queue parameters"))
                }
                Some("--per-queue") => {
                    Ok("Queue: 0\nAdaptive RX: on  TX: on\nrx-usecs: 32\n".to_owned())
                }
                Some("-N") => Ok("Added rule with ID 1023\n".to_owned()),
                _ => Ok(String::new()),
            }
        }

        fn read(&self, path: &Path) -> io::Result<String> {
            if path == Path::new("/proc/net/route") {
                return Ok(self.routes.to_owned());
            }
            if path == Path::new("/proc/interrupts") {
                return Ok(self.interrupts.to_owned());
            }
            // A `/sys` file that no test seeded holds whatever the kernel shipped, which for
            // every file this module writes is zero.
            Ok(self
                .files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .unwrap_or_else(|| "0\n".to_owned()))
        }

        fn write(&self, path: &Path, value: &str) -> io::Result<()> {
            self.refuse(&format!("write {} {value}", path.display()))?;
            self.files
                .lock()
                .unwrap()
                .insert(path.to_owned(), value.to_owned());
            Ok(())
        }
    }

    /// A card that refuses one step is a card, not a broken host. §11 wants the overlay's queue
    /// pinned whether or not the flow rule for one address family took, so the plan runs to the
    /// end and the report names what did not happen.
    #[test]
    fn apply_failure_of_one_action_reports_it_and_continues_with_the_rest() {
        let nic = Fake {
            fails: Some("flow-type udp6"),
            ..Fake::default()
        };
        let plan = plan(&caps(true), &cfg(Steering::Auto), PORT);

        let report = apply_with(&nic, &plan);

        assert_eq!(
            report.applied,
            vec![
                Action::NtupleRule {
                    iface: "eth0".to_owned(),
                    flow_type: "udp4",
                    port: PORT,
                    queue: 7,
                },
                Action::IrqAffinity {
                    iface: "eth0".to_owned(),
                    queue: 7,
                    cpu: 31,
                },
                Action::ThreadedNapi {
                    iface: "eth0".to_owned(),
                },
            ]
        );
        let (refused, said) = report.failed.first().expect("the udp6 rule");
        assert_eq!(
            *refused,
            Action::NtupleRule {
                iface: "eth0".to_owned(),
                flow_type: "udp6",
                port: PORT,
                queue: 7,
            }
        );
        assert!(said.contains("device refused"), "{said}");
        assert_eq!(report.failed.len(), 1);

        // The interrupt moved and threaded NAPI came on, which is the point of carrying on.
        assert_eq!(
            nic.read(Path::new("/proc/irq/131/smp_affinity_list")).ok(),
            Some("31".to_owned())
        );
        assert_eq!(
            nic.read(Path::new("/sys/class/net/eth0/threaded")).ok(),
            Some("1".to_owned())
        );
    }

    /// Undo is what keeps a host from being left tuned by a sidecar that has stopped: every
    /// applied action goes back to what it displaced, newest first.
    #[test]
    fn undo_puts_back_what_the_plan_displaced() {
        let nic = Fake::default();
        let report = apply_with(&nic, &plan(&caps(true), &cfg(Steering::Auto), PORT));

        undo_with(&nic, &report);

        assert_eq!(
            nic.read(Path::new("/proc/irq/131/smp_affinity_list")).ok(),
            Some("0\n".to_owned())
        );
        assert_eq!(
            nic.read(Path::new("/sys/class/net/eth0/threaded")).ok(),
            Some("0\n".to_owned())
        );
        assert!(
            nic.calls()
                .iter()
                .any(|call| call == "ethtool -N eth0 delete 1023"),
            "{:?}",
            nic.calls()
        );
    }

    /// The shipped default (D30), all the way down: an operator who never set `steering` has a
    /// host nothing here has spoken to. Not one `ethtool` run, not one file written.
    #[test]
    fn steering_off_asks_the_host_for_nothing() {
        let nic = Fake::default();

        let report = enable_with(&nic, &cfg(Steering::Off), PORT);

        assert!(nic.calls().is_empty(), "{:?}", nic.calls());
        assert!(report.applied.is_empty());
        assert!(report.failed.is_empty());
    }

    /// The three questions a plan is computed from, asked of one card and answered from its own
    /// `ethtool` output.
    #[test]
    fn detect_reads_the_card_behind_the_default_route() {
        let nic = Fake::default();

        let caps = detect_with(&nic).expect("the fixture card");

        assert_eq!(
            caps,
            NicCaps {
                iface: "eth0".to_owned(),
                rx_queues: 16,
                ntuple: true,
                per_queue_coalesce: false,
            }
        );
    }

    /// The port the overlay listens on everywhere in the shipped configuration. Nothing in
    /// `plan` reads it apart from putting it in the rule, so one value is enough.
    const PORT: u16 = 7788;

    /// A NIC with eight receive queues, which is what a mid-range card gives a 32-core host.
    fn caps(ntuple: bool) -> NicCaps {
        NicCaps {
            iface: "eth0".to_owned(),
            rx_queues: 8,
            ntuple,
            per_queue_coalesce: false,
        }
    }

    /// The reserved core §11 puts the sidecar on, since every action but the steering rule
    /// itself is about which core the work lands on.
    fn cfg(steering: Steering) -> IoThread {
        IoThread {
            pin_cpu: Some(31),
            steering,
            ..IoThread::default()
        }
    }

    /// The whole point of §11: one flow rule per address family, because the overlay listens on
    /// `[::]` and takes both, and the queue they land on pinned to the reserved core.
    #[test]
    fn plan_with_ntuple_support_produces_two_rules_and_irq_affinity() {
        let plan = plan(&caps(true), &cfg(Steering::Auto), PORT);

        assert_eq!(
            plan,
            vec![
                Action::NtupleRule {
                    iface: "eth0".to_owned(),
                    flow_type: "udp4",
                    port: PORT,
                    queue: 7,
                },
                Action::NtupleRule {
                    iface: "eth0".to_owned(),
                    flow_type: "udp6",
                    port: PORT,
                    queue: 7,
                },
                Action::IrqAffinity {
                    iface: "eth0".to_owned(),
                    queue: 7,
                    cpu: 31,
                },
                Action::ThreadedNapi {
                    iface: "eth0".to_owned(),
                },
            ]
        );
    }

    /// A NIC with no ntuple support still steers, through the kernel rather than the card: RFS
    /// sends the overlay socket's flow to the core that reads it (§11).
    #[test]
    fn plan_without_ntuple_falls_back_to_rfs() {
        let plan = plan(&caps(false), &cfg(Steering::Auto), PORT);

        assert_eq!(
            plan,
            vec![
                Action::RfsFlowEntries {
                    iface: "eth0".to_owned(),
                    queue: 7,
                    entries: 4096,
                },
                Action::IrqAffinity {
                    iface: "eth0".to_owned(),
                    queue: 7,
                    cpu: 31,
                },
                Action::ThreadedNapi {
                    iface: "eth0".to_owned(),
                },
            ]
        );
    }

    /// The shipped default (D30). Nothing is planned, so nothing is applied and no NIC is
    /// touched on a host whose operator never asked for any of this.
    #[test]
    fn plan_with_steering_off_is_empty() {
        assert!(plan(&caps(true), &cfg(Steering::Off), PORT).is_empty());
    }

    /// `ethtool`'s output is the only thing that says which branch of [`plan`] a host takes, and
    /// it is a human-readable format with no promise behind it. Two cards, one that can steer a
    /// flow itself and one that cannot, in whole: a fixture cut down to the two lines the parser
    /// reads would stop proving that the rest is skipped.
    #[test]
    fn parses_ethtool_features_output_fixtures() {
        // ConnectX-5 ships with the filter off, but not `[fixed]`, so it can be turned on.
        assert!(supports_ntuple(include_str!(
            "steering/fixtures/mlx5-connectx5-features.txt"
        )));
        // A virtio interface has no filter to turn on, which is what `off [fixed]` means.
        assert!(!supports_ntuple(include_str!(
            "steering/fixtures/virtio-net-features.txt"
        )));

        // The running channel count, not the card's maximum: the queue the overlay takes has to
        // exist now.
        assert_eq!(
            rx_queues(include_str!(
                "steering/fixtures/mlx5-connectx5-channels.txt"
            )),
            Some(16)
        );
        assert_eq!(
            rx_queues(include_str!("steering/fixtures/virtio-net-channels.txt")),
            Some(4)
        );
    }

    /// §11 leaves coalescing alone unless it can be changed for one queue: a global change
    /// would raise the interrupt rate for the beacon node's traffic too.
    #[test]
    fn plan_includes_per_queue_coalesce_only_when_supported() {
        let without = plan(&caps(true), &cfg(Steering::Auto), PORT);
        assert!(
            !without
                .iter()
                .any(|action| matches!(action, Action::PerQueueCoalesce { .. }))
        );

        let supported = NicCaps {
            per_queue_coalesce: true,
            ..caps(true)
        };

        let with = plan(&supported, &cfg(Steering::Auto), PORT);

        assert_eq!(
            with.last(),
            Some(&Action::PerQueueCoalesce {
                iface: "eth0".to_owned(),
                queue: 7,
                rx_usecs: 8,
            })
        );
    }
}
