//! Compile-only control (design F5 §9.3): `--cfg f5_raw_session_write` must fail the raw-write ban in this crate.
//! Proves the write-intent `OpenOptions` builder entries resolve (a read-only `open` stays allowed).
#![allow(dead_code, unexpected_cfgs)]

#[cfg(f5_raw_session_write)]
fn raw_session_append(session_dir: &std::path::Path) {
    let _ = std::fs::OpenOptions::new().append(true).open(session_dir.join("events.jsonl"));
}

fn main() {}
