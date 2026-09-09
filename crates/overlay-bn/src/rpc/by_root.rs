//! The optional by-root cache: the sidecar answers its own beacon node's `BeaconBlocksByRoot`
//! and `DataColumnSidecarsByRoot` lookups out of the payloads it already holds (§5.8, T-085).
//!
//! Lighthouse does not prefer trusted peers when it picks who to ask, so a lookup lands here
//! only sometimes. When it does, a missing-parent recovery is a localhost round trip instead of
//! a public one, and when it does not, the beacon node is exactly where it was. That is why the
//! whole thing is behind `bn.by_root_cache.enabled` and ships off.
//!
//! Nothing here is served to overlay peers. The recent store answers a sibling's repair request
//! by message id or by column identity (T-082, T-083); this answers the one peer on the other
//! end of the localhost link, in the beacon node's own protocol.
//!
//! # What is trusted and what is not
//!
//! The store's index is filled from headers a peer chose and nobody verified (MD-06), so a
//! forged sidecar could make this host answer for a root it never saw. That costs the beacon
//! node one failed lookup: it verifies everything the sidecar hands it, the same as it verifies
//! what a public peer hands it, and a block that does not check out is dropped. The store's
//! first-writer-wins rule is what keeps a forgery from displacing a real payload.

#[cfg(feature = "by-root-cache")]
mod on {
    use overlay_core::msgid::MessageId;
    use overlay_core::recent::SharedRecentLarge;
    use overlay_core::wire::MAX_PAYLOAD_BYTES;
    use ssz::Decode;
    use types::{DataColumnsByRootIdentifier, Hash256, MainnetEthSpec};

    use crate::rpc::proto::Protocol;
    use crate::rpc::{ByRootCache, Chunk, MAX_REQUEST_BLOCKS, Response};

    /// The answer to a by-root `request` received on `protocol`.
    ///
    /// A request that names nothing this host holds, and a body that is not the request its
    /// protocol carries, both come back `ResourceUnavailable`: that is what these two protocols
    /// answered before the cache existed, so a beacon node whose lookup misses is no worse off
    /// than it was. A request that names more than one object is answered with a chunk for each
    /// one found, in the order it asked, which is what Lighthouse reads a partial answer as.
    pub fn answer(cache: &ByRootCache, protocol: Protocol, request: &[u8]) -> Response {
        if !cache.enabled() {
            return Response::ResourceUnavailable;
        }
        let chunks = match protocol {
            Protocol::BlocksByRootV2 => blocks(&cache.recent, request),
            Protocol::ColumnsByRootV1 => columns(&cache.recent, request),
            _ => return Response::ResourceUnavailable,
        };
        cache.stats.by_root_request(protocol, !chunks.is_empty());
        match chunks.is_empty() {
            true => Response::ResourceUnavailable,
            false => Response::Chunks(chunks),
        }
    }

    /// `BlocksByRootRequest`: an SSZ list of block roots, which is a fixed-size element type and
    /// so is the roots one after another.
    fn blocks(recent: &SharedRecentLarge, request: &[u8]) -> Vec<Chunk> {
        let Ok(roots) = Vec::<Hash256>::from_ssz_bytes(request) else {
            return Vec::new();
        };
        roots
            .iter()
            .take(MAX_REQUEST_BLOCKS)
            .filter_map(|root| chunk(recent, recent.get_by_block(bytes32(root))?))
            .collect()
    }

    /// `DataColumnsByRootRequest`: an SSZ list of `(block_root, indices)`, whose elements are
    /// variable-size and so are offset-prefixed. `types` owns both shapes, so the request the
    /// beacon node built and the request this reads cannot drift apart.
    ///
    /// Only the indices asked for are served. A host in full custody holds all 128 columns of a
    /// block, and sending the ones the beacon node did not ask about would be five megabytes
    /// over the link for nothing.
    fn columns(recent: &SharedRecentLarge, request: &[u8]) -> Vec<Chunk> {
        let Ok(ids) = Vec::<DataColumnsByRootIdentifier<MainnetEthSpec>>::from_ssz_bytes(request)
        else {
            return Vec::new();
        };
        ids.iter()
            .take(MAX_REQUEST_BLOCKS)
            .flat_map(|id| {
                let root = bytes32(&id.block_root);
                id.columns.iter().filter_map(move |index| {
                    let index = u8::try_from(*index).ok()?;
                    Some((root, index))
                })
            })
            .filter_map(|(root, index)| chunk(recent, recent.get_by_column(root, index)?))
            .collect()
    }

    /// The chunk for the payload held under `msg_id`: its SSZ, and the fork digest of the topic
    /// it arrived on, which is the fork the beacon node itself put the object under.
    ///
    /// The store keeps the compressed form every other consumer wants, so a served object is
    /// decompressed here. That is tens of microseconds against the tens of milliseconds a
    /// public round trip would have cost, and it happens only on a hit.
    fn chunk(recent: &SharedRecentLarge, msg_id: MessageId) -> Option<Chunk> {
        let (topic, payload) = recent.get(&msg_id)?;
        Some(Chunk {
            context: topic.fork_digest(),
            ssz: overlay_core::msgid::decompressed(&payload, MAX_PAYLOAD_BYTES)?,
        })
    }

    fn bytes32(root: &Hash256) -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(root.as_slice());
        out
    }
}

#[cfg(not(feature = "by-root-cache"))]
mod on {
    use crate::rpc::proto::Protocol;
    use crate::rpc::{ByRootCache, Response};

    /// The refusal T-019 gives, for a build without the cache compiled in.
    pub fn answer(_: &ByRootCache, _: Protocol, _: &[u8]) -> Response {
        Response::ResourceUnavailable
    }
}

pub use on::answer;
