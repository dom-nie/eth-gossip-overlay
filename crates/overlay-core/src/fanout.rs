//! What leaves this host for the overlay. Today only the item the inbound path (T-016) hands
//! over; T-032 grows this module into the fanout task that takes it, asks the router (T-031)
//! where it goes and writes the frames.

use std::time::Instant;

use bytes::Bytes;

use crate::msgid::MessageId;
use crate::topic::{Class, Topic};

/// A message the beacon node delivered, ready for the router. The payload is still in its
/// compressed wire form, which is what the overlay carries; nothing on this path decompresses.
#[derive(Clone, Debug)]
pub struct Outbound {
    /// The topic it arrived on.
    pub topic: Topic,
    /// [`Class::of`] the topic's kind and the payload length (D02), carried so the send side
    /// labels its metrics without parsing the topic again.
    pub class: Class,
    /// The id gossipsub computed, which is the beacon node's id for it.
    pub id: MessageId,
    /// The snappy-compressed payload.
    pub payload: Bytes,
    /// When the inbound task took it off the link's lane, by the injected clock, so latency
    /// metrics built on it can be tested.
    pub received_at: Instant,
}
