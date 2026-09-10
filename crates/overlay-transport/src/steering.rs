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

#[cfg(test)]
mod tests {
    use overlay_core::config::{IoThread, Steering};

    use super::*;

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
