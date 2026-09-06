//! Writes `tests/vectors/v1`, one file per frame variant, from the same values the codec tests
//! use. Run it with `cargo run -p overlay-core --example gen_vectors` after adding a variant; on
//! an unchanged tree it rewrites the files byte for byte and leaves `git status` clean.
//!
//! The corpus is frozen: a file that changes means the layout changed, and every release after
//! this one has to decode these bytes.

use std::path::Path;

use bytes::BytesMut;

#[path = "../tests/common/mod.rs"]
mod common;

fn main() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1");
    std::fs::create_dir_all(&dir)?;

    for (name, frame) in common::samples() {
        let mut out = BytesMut::new();
        frame.encode(&mut out);
        std::fs::write(dir.join(format!("{name}.bin")), &out)?;
    }
    Ok(())
}
