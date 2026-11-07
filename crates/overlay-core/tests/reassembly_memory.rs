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
use overlay_core::budget::REASSEMBLY_ENTRY_BYTES;
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

/// A frame body of `frame_len` bytes read the way `wire::read_frame` reads one, into one `Vec`
/// handed to `Bytes`, and the `data_len` bytes at its end cut out with `split_to` as the codec
/// cuts a chunk's data.
fn view_into_frame(frame_len: usize, data_len: usize) -> Bytes {
    let mut frame = Bytes::from(vec![0xa5; frame_len]);
    drop(frame.split_to(frame_len - data_len));
    frame.split_to(data_len)
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

/// One 2-byte chunk of message `message`, a split of 65535 data chunks and no parity, viewed
/// from a 40-byte `CHUNK` frame of its own.
fn two_byte_chunk(message: u32, index: u16) -> Chunk {
    let mut msg_id = [0; 20];
    msg_id[..4].copy_from_slice(&message.to_le_bytes());
    Chunk {
        msg_id: MessageId(msg_id),
        topic_id: 1,
        k: u16::MAX,
        m: 0,
        index,
        total_len: u32::from(u16::MAX) * 2,
        data: view_into_frame(40, 2),
    }
}

/// What the heap may have grown by while `reassembler` holds what it holds: the cap, plus what
/// the budget prices per open entry as `REASSEMBLY_ENTRY_BYTES`, plus the harness's own room.
fn allowed(reassembler: &Reassembler, max_bytes: usize) -> usize {
    max_bytes + reassembler.in_flight() * REASSEMBLY_ENTRY_BYTES as usize + HARNESS_BYTES
}

fn four_mib_reassembler() -> (Reassembler, usize) {
    let max_bytes = 4 * 1024 * 1024;
    let reassembler = Reassembler::new(ReassembleConfig {
        max_bytes,
        ..ReassembleConfig::default()
    });
    (reassembler, max_bytes)
}

/// A roster peer cutting 2-byte chunks, each in a `CHUNK` frame of its own, makes this host hold
/// tens of thousands of them, and what they cost on the heap, their slots and their copies,
/// stays inside `max_bytes`. The flood holds one or two entries at a time, so it says little
/// about the bitmaps; `one_chunk_at_the_last_index_per_message_keeps_the_heap_under_max_bytes`
/// is the test for those.
#[test]
fn a_two_byte_chunk_flood_keeps_the_heap_under_max_bytes() {
    let _serial = serial();
    let (reassembler, max_bytes) = four_mib_reassembler();
    let (topic, from) = (block(), host());
    let now = Instant::now();
    // Each message stops one index short so none completes and everything sent is held.
    let per_message = u32::from(u16::MAX) - 1;
    let before = live();
    let mut worst = 0;

    for sent in 0..400_000u32 {
        let chunk = two_byte_chunk(sent / per_message, (sent % per_message) as u16);
        reassembler.on_chunk(&chunk, &topic, &from, false, now);
        drop(chunk);

        let grown = live().saturating_sub(before);
        let allowed = allowed(&reassembler, max_bytes);
        worst = worst.max(grown);
        assert!(
            grown <= allowed,
            "{grown} bytes live after {sent} chunks, {allowed} allowed"
        );
    }
    println!("worst live heap growth over the flood: {worst} bytes, cap {max_bytes}");
}

/// One chunk at the last index of a 65535-chunk split opens an entry whose two bitmaps take
/// 16 KiB for 2 bytes of payload. Spread over as many messages as the count bound allows, that
/// is 8 MiB nothing would count if the bitmaps were not charged when the entry opens.
#[test]
fn one_chunk_at_the_last_index_per_message_keeps_the_heap_under_max_bytes() {
    let _serial = serial();
    let (reassembler, max_bytes) = four_mib_reassembler();
    let (topic, from) = (block(), host());
    let now = Instant::now();
    let before = live();
    let mut worst = 0;

    for message in 0..512 {
        let chunk = two_byte_chunk(message, u16::MAX - 1);
        reassembler.on_chunk(&chunk, &topic, &from, false, now);
        drop(chunk);

        let grown = live().saturating_sub(before);
        let allowed = allowed(&reassembler, max_bytes);
        worst = worst.max(grown);
        assert!(
            grown <= allowed,
            "{grown} bytes live after {message} messages, {allowed} allowed, {} in flight",
            reassembler.in_flight()
        );
    }
    println!(
        "worst live heap growth over 512 last-index chunks: {worst} bytes, cap {max_bytes}, {} in flight",
        reassembler.in_flight()
    );
}
