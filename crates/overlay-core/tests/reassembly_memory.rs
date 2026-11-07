//! What the reassembler really holds on the heap, measured by an allocator that counts live
//! bytes, against what its byte cap says it holds (MD-11 amended).
//!
//! A `#[global_allocator]` is per binary, which is why this is a test binary of its own. It
//! counts requested sizes, so allocator rounding is not in the numbers; `CHUNK_OVERHEAD_BYTES`
//! carries a margin for that.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use bytes::Bytes;
use overlay_core::msgid::MessageId;
use overlay_core::reassemble::{Outcome, ReassembleConfig, Reassembler};
use overlay_core::roster::Hostname;
use overlay_core::topic::Topic;
use overlay_core::wire::Chunk;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call is passed straight to `System` with the caller's arguments, and the count
// is only ever read, never used to decide anything about an allocation.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The count is process-wide, so two tests measuring at once would read each other's bytes.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Room for what the test harness itself allocates on other threads while a test measures.
const HARNESS_BYTES: usize = 64 * 1024;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn block() -> Topic {
    Topic::parse("/eth2/6a95a1a9/beacon_block/ssz_snappy").unwrap_or_else(|_| unreachable!())
}

fn host() -> Hostname {
    Hostname("bn-01".to_owned())
}

/// A repair answer carries many chunks in one frame of up to 10 MiB, so a chunk kept as a view
/// into it would keep all of it. The entry has to own its bytes.
#[test]
fn a_chunk_cut_from_a_large_frame_does_not_keep_the_frame() {
    let _serial = serial();
    let reassembler = Reassembler::new(ReassembleConfig::default());
    let (topic, from) = (block(), host());
    let before = live();

    let mut frame = Bytes::from(vec![0xa5; 1024 * 1024]);
    let chunk = Chunk {
        msg_id: MessageId([1; 20]),
        topic_id: 1,
        k: 2,
        m: 0,
        index: 0,
        total_len: 4096,
        data: frame.split_to(2048),
    };
    let outcome = reassembler.on_chunk(&chunk, &topic, &from, false, Instant::now());
    drop((chunk, frame));

    let grown = live().saturating_sub(before);
    println!("live heap growth with one 2048-byte chunk held: {grown} bytes");
    assert_eq!(outcome, Outcome::Stored { forward: true });
    assert!(
        grown < HARNESS_BYTES,
        "{grown} bytes still live for one 2048-byte chunk"
    );
}
