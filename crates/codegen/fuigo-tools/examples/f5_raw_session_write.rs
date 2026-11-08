//! Compile-only control (design F5 §9.3): `--cfg f5_raw_session_write` must fail the raw-write ban in this crate.
//! Proves a second listed crate reads its own clippy.toml, through a `tokio::fs` entry.
#![allow(dead_code, unexpected_cfgs)]

#[cfg(f5_raw_session_write)]
async fn raw_session_rename(session_dir: &std::path::Path) {
    let _ = tokio::fs::rename(session_dir.join("summary.json.tmp"), session_dir.join("summary.json")).await;
}

fn main() {}
