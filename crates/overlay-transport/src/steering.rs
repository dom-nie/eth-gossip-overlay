//! Steering the overlay's UDP traffic to a NIC queue of its own (§11).

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
        assert!(!without.iter().any(|action| matches!(
            action,
            Action::PerQueueCoalesce { .. }
        )));

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
