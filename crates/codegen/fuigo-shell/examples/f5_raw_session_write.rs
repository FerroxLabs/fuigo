//! Compile-only control (design F5 §9.3): `--cfg f5_raw_session_write` must fail the raw-write ban in this crate.
//! Proves the std entries of `session-writer-crates.toml` `raw-write-ban` are active in fuigo-shell.
#![allow(dead_code, unexpected_cfgs)]

#[cfg(f5_raw_session_write)]
fn raw_session_write(session_dir: &std::path::Path) {
    let _ = std::fs::write(session_dir.join("chat_history.jsonl"), b"{}\n");
    let _ = std::fs::DirBuilder::new().create(session_dir.join("images"));
}

fn main() {}
