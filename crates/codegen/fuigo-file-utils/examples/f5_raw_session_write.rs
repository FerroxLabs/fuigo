//! Compile-only control (design F5 §9.3): `--cfg f5_raw_session_write` must fail the producer ban.
//! fuigo-file-utils is not a listed session-writer crate, so it inherits the root clippy.toml: computing a
//! session-folder path there fails until the crate is listed in session-writer-crates.toml or allowed with a reason.
#![allow(dead_code, unexpected_cfgs)]

#[cfg(f5_raw_session_write)]
fn new_crate_computes_session_path(fuigo_home: &std::path::Path) -> std::path::PathBuf {
    fuigo_config::sessions_cwd_dir_in(fuigo_home, "/work/project")
}

fn main() {}
