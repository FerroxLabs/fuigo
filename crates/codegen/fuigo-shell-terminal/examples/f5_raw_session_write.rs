//! Compile-only control (design F5 §9.3): `--cfg f5_raw_session_write` must fail the raw-write ban in this crate.
//! Proves a defining-path helper entry is spelled right: the call goes through the `fuigo_config` re-export, the ban
//! names `fuigo_config::paths::create_file_owner_only`.
#![allow(dead_code, unexpected_cfgs)]

#[cfg(f5_raw_session_write)]
fn raw_session_log(session_dir: &std::path::Path) {
    let _ = fuigo_config::create_file_owner_only(&session_dir.join("terminal").join("1.log"));
}

fn main() {}
