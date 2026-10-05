//! R077: a malformed TIFF must be rejected, not crash the process when stderr is gone.
//!
//! tiff 0.11.3 wrapped its `LimitsExceeded` error for an oversized ASCII tag in `dbg!`, a raw
//! stderr print. Release is `panic = "abort"`, so with fd 2 a dead pipe or `/dev/full` a
//! 26-byte header (ImageWidth typed ASCII, declaring a 256 MiB + 1 value) aborted the process
//! during image header probing, before fuigo's own pixel budget ran. The vendored tiff
//! (third_party/tiff-0.11.3) returns the error without printing.
//!
//! A child process runs fuigo-tools' image paths on that header with its panic hook set to
//! abort (as release does); the parent attaches stderr live, as a dead pipe and as `/dev/full`.
#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const CHILD_ENV: &str = "FUIGO_R077_TIFF_CHILD";

/// Little-endian TIFF: one IFD, one entry: tag 256 (ImageWidth), type 2 (ASCII), count
/// 0x1000_0001 (one byte over tiff's 256 MiB default `decoding_buffer_size`), offset 0.
fn oversized_ascii_tiff() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"II*\0");
    b.extend_from_slice(&8u32.to_le_bytes()); // first IFD
    b.extend_from_slice(&1u16.to_le_bytes()); // one entry
    b.extend_from_slice(&256u16.to_le_bytes()); // ImageWidth
    b.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    b.extend_from_slice(&0x1000_0001u32.to_le_bytes()); // count
    b.extend_from_slice(&0u32.to_le_bytes()); // value offset
    b.extend_from_slice(&0u32.to_le_bytes()); // no next IFD
    b
}

#[derive(Clone, Copy, Debug)]
enum Stderr {
    Live,
    DeadPipe,
    #[cfg(target_os = "linux")]
    Full,
}

fn run_child(mode: Stderr) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().expect("test binary"));
    command
        .args(["--exact", "tiff_child", "--ignored", "--nocapture"])
        .env(CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let mut dead_reader = None;
    match mode {
        Stderr::Live => {
            command.stderr(Stdio::piped());
        }
        Stderr::DeadPipe => {
            let (reader, writer) = std::io::pipe().expect("pipe");
            command.stderr(Stdio::from(writer));
            dead_reader = Some(reader);
        }
        #[cfg(target_os = "linux")]
        Stderr::Full => {
            let full = std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full");
            command.stderr(Stdio::from(full));
        }
    }
    drop(dead_reader);
    #[allow(
        clippy::disallowed_methods,
        reason = "output() waits for the child, so it never outlives this function"
    )]
    let output = command.output().expect("spawn child");
    output
}

/// The child half: header probing and the transcode path, both must return an error.
#[test]
#[ignore = "run only as the child of the tests below"]
fn tiff_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    std::panic::set_hook(Box::new(|_| std::process::abort()));
    let bytes = oversized_ascii_tiff();
    use fuigo_tools::util::image_validate as iv;
    assert!(iv::validate_image_bytes_with(&bytes, false).is_err());
    assert!(iv::validate_image_bytes_with(&bytes, true).is_err());
    assert!(matches!(
        iv::transcode_to_endpoint_png(&bytes),
        Some(Err(_))
    ));
    println!("R077_TIFF_CHILD_DONE");
}

fn assert_child_survives(mode: Stderr) {
    let out = run_child(mode);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && out.status.signal().is_none(),
        "stderr {mode:?}: expected a clean rejection, got {:?} (signal {:?}; 6 = SIGABRT from a \
         panicking print)\nstdout:\n{stdout}",
        out.status,
        out.status.signal()
    );
    assert!(stdout.contains("R077_TIFF_CHILD_DONE"), "{stdout}");
}

/// Control: the header is rejected and nothing is printed to stderr (the old `dbg!` printed
/// `TiffError::LimitsExceeded` here).
#[test]
fn an_oversized_ascii_tag_is_rejected_silently() {
    let out = run_child(Stderr::Live);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{:?}\n{stderr}", out.status);
    assert!(!stderr.contains("LimitsExceeded"), "{stderr}");
}

#[test]
fn an_oversized_ascii_tag_with_a_dead_stderr_is_rejected_not_fatal() {
    assert_child_survives(Stderr::DeadPipe);
}

#[cfg(target_os = "linux")]
#[test]
fn an_oversized_ascii_tag_with_a_full_stderr_is_rejected_not_fatal() {
    assert_child_survives(Stderr::Full);
}

/// `(entries, non-local versions)` for package `name` in a `Cargo.lock`: an entry with a
/// `source` line comes from a registry or git, one without is a path (vendored) package.
fn lock_entries(lock: &str, name: &str) -> (usize, Vec<String>) {
    let wanted = format!("\"{name}\"");
    let mut total = 0;
    let mut non_local = Vec::new();
    for block in lock.split("[[package]]") {
        // Keys are matched after trimming and up to `=`: indentation and spacing are valid TOML.
        let value = |key: &str| {
            block.lines().find_map(|line| {
                let rest = line.trim().strip_prefix(key)?.trim_start();
                Some(rest.strip_prefix('=')?.trim())
            })
        };
        if value("name") != Some(wanted.as_str()) {
            continue;
        }
        total += 1;
        if value("source").is_some() {
            let version = value("version").unwrap_or("?");
            non_local.push(version.trim_matches('"').to_string());
        }
    }
    (total, non_local)
}

/// `[patch.crates-io]` only replaces the versions the vendored copies declare. A `cargo update`
/// that moves tiff or usvg to another version would silently resolve back to crates.io and to
/// its raw prints (R077, Astra r6). The lockfile must keep both on the local copies.
#[test]
fn tiff_and_usvg_resolve_to_the_print_free_vendored_copies() {
    let lock_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../Cargo.lock");
    let lock = std::fs::read_to_string(lock_path).expect("workspace Cargo.lock");
    for name in ["tiff", "usvg"] {
        let (total, non_local) = lock_entries(&lock, name);
        assert!(
            total >= 1,
            "{name} is no longer in Cargo.lock; drop its vendored copy"
        );
        assert!(
            non_local.is_empty(),
            "{name} {non_local:?} resolves to a registry/git source, bypassing \
             third_party/{name}-*: re-vendor that version without its prints (third_party/README.md)"
        );
    }
    // The checker does see a registry entry.
    let registry = "[[package]]\nname = \"tiff\"\nversion = \"0.11.4\"\n\
                    source = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    assert_eq!(
        lock_entries(registry, "tiff"),
        (1, vec!["0.11.4".to_string()])
    );
    assert_eq!(lock_entries(registry, "usvg"), (0, Vec::new()));
    // Indented keys and a git source are seen too; a second, local entry does not hide them.
    let mixed = "[[package]]\nname = \"usvg\"\nversion = \"0.47.0\"\n\n\
                 [[package]]\n  name=\"usvg\"\n  version = \"0.48.0\"\n  \
                 source = \"git+https://github.com/linebender/resvg#abc\"\n";
    assert_eq!(lock_entries(mixed, "usvg"), (2, vec!["0.48.0".to_string()]));
}
