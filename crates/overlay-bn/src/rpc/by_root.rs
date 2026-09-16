//! The optional by-root cache: the sidecar answers its own beacon node's `BeaconBlocksByRoot`
//! and `DataColumnSidecarsByRoot` lookups out of the payloads it already holds (§5.8, T-085).
//!
//! In practice only the block half is asked. Lighthouse requests columns from the peers it has
//! assigned custody subnets to, and the sidecar answers MetaData without a custody group count
//! so that it is never one of them (`proto`, T-102). The column handler stays, since the
//! store holds the columns either way and the handler is the small part, but nothing calls it
//! until a release changes who the node asks.
//!
//! Lighthouse does not prefer trusted peers when it picks who to ask, so a lookup lands here
//! only sometimes. When it does, a missing-parent recovery is a localhost round trip instead of
//! a public one, and when it does not, the beacon node is exactly where it was. That is why the
//! whole thing is behind `bn.by_root_cache.enabled` and ships off.
//!
//! It is behind the inject kill switch as well (§5.7). An answer here is overlay-delivered bytes
//! handed to the beacon node, the same as a publish, only on the node's own request, so
//! `inject: false` refuses it. The flag is the one the publisher reads, not a second switch.
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
//! first-claim rule keeps whichever payload claimed the root first, a forgery included; what it
//! rules out is a later arrival, real or forged, taking the claim over.
//!
//! Repair serves a column to a peer only once `custody.holds` says this host's own node
//! verified it (T-087). Nothing gates this path the same way, and D39 left it so on purpose:
//! the consumer is the node itself, which validates what it is handed and has no path back into
//! the store, so a forgery served here costs one failed localhost lookup and goes no further.
//! That is the whole cost, which is why the cache keeps first-claim as it is rather than taking
//! D39's option B, a node claim displacing a peer claim, for it.

use overlay_core::msgid::MessageId;
use overlay_core::recent::SharedRecentLarge;
use overlay_core::wire::MAX_PAYLOAD_BYTES;
use ssz::Decode;
use types::{DataColumnsByRootIdentifier, Hash256, MainnetEthSpec};

use crate::rpc::proto::Protocol;
use crate::rpc::{ByRootCache, ByRootOutcome, Chunk, MAX_REQUEST_BLOCKS, Response};

/// The answer to a by-root `request` received on `protocol`.
///
/// A request that names nothing this host holds, and a body that is not the request its
/// protocol carries, both come back `ResourceUnavailable`: that is what these two protocols
/// answered before the cache existed, so a beacon node whose lookup misses is no worse off
/// than it was. A request that names more than one object is answered with a chunk for each
/// one found, in the order it asked, which is what Lighthouse reads a partial answer as.
/// While the cache or inject is off every request is refused the same way, uncounted: a
/// refusal is neither a hit nor a miss.
pub fn answer(cache: &ByRootCache, protocol: Protocol, request: &[u8]) -> Response {
    if !cache.enabled() || !cache.inject() {
        return Response::ResourceUnavailable;
    }
    let chunks = match protocol {
        Protocol::BlocksByRootV2 => blocks(&cache.recent, request),
        Protocol::ColumnsByRootV1 => columns(&cache.recent, request),
        _ => return Response::ResourceUnavailable,
    };
    match chunks.is_empty() {
        true => {
            cache.stats.by_root_request(protocol, ByRootOutcome::Miss);
            Response::ResourceUnavailable
        }
        false => {
            cache.stats.by_root_request(protocol, ByRootOutcome::Hit);
            Response::Chunks(chunks)
        }
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

#[cfg(test)]
mod tests {
    use types::{EthSpec, GnosisEthSpec, MainnetEthSpec, MinimalEthSpec};

    /// `columns` reads a `DataColumnsByRootIdentifier<MainnetEthSpec>` whatever network the
    /// beacon node runs, which is sound only while `NumberOfColumns` is the same on every
    /// preset: it is the one type parameter the request's shape depends on. It is U128 on all
    /// three at v8.2.2, and this is where a Lighthouse bump that changes that fails, rather
    /// than in a lookup (D38).
    #[test]
    fn number_of_columns_agrees_across_the_three_presets() {
        let mainnet = MainnetEthSpec::number_of_columns();

        assert_eq!(mainnet as u64, crate::spec::MAINNET.number_of_columns);
        assert_eq!(MinimalEthSpec::number_of_columns(), mainnet);
        assert_eq!(GnosisEthSpec::number_of_columns(), mainnet);
    }
}
