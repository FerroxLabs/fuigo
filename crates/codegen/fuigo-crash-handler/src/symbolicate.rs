//! Backtrace symbolication for crash reports.
//!
//! Runs at normal startup (not in a signal handler), so full Rust APIs are
//! available. The blob holds absolute instruction pointers from the crashed
//! process; under ASLR the reader's image sits elsewhere, so each pointer
//! inside the crashed main image is turned into a module-relative offset and
//! re-based onto the reader's own image before resolving — and only when the
//! reader is the same build (identity check). Otherwise the report keeps
//! the raw module offsets, which `addr2line`/`atos` can resolve offline
//! against the matching binary.

use crate::format::{CrashBlob, CrashKind, ImageInfo, PanicClass};

/// A resolved backtrace frame.
#[derive(Debug, Clone)]
pub struct ResolvedFrame {
    /// Absolute instruction pointer in the crashed process.
    pub ip: usize,
    /// Offset into the crashed main image, when the frame lies inside it.
    pub module_offset: Option<u64>,
    pub symbol_name: Option<String>,
    pub filename: Option<String>,
    pub lineno: Option<u32>,
}

/// Why frames were or were not symbolicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbolication {
    /// Re-based onto this process's image and resolved.
    Resolved,
    /// The crash came from a different build; offsets only.
    DifferentBuild,
    /// The crashed binary carried no identity (no build id and no file
    /// fingerprint), so a match cannot be verified; offsets only.
    UnverifiedBuild,
    /// Old-format blob (absolute addresses, no image base); not resolved.
    LegacyFormat,
    /// The crashed or current image could not be located; not resolved.
    NoImage,
}

/// The current process's view of itself, used to decide whether a blob
/// can be symbolicated here.
#[derive(Debug, Clone, Copy)]
pub struct LocalImage<'a> {
    pub image: Option<ImageInfo>,
    pub exe_len: u64,
    /// Expected app version; empty = don't compare.
    pub app_version: &'a str,
}

impl LocalImage<'_> {
    pub fn current(app_version: &str) -> LocalImage<'_> {
        LocalImage {
            image: crate::image::current_image(),
            exe_len: crate::image::current_exe_len(),
            app_version,
        }
    }
}

/// Is `blob` from the same binary as `local`? Requires a known identity on
/// both sides: two binaries without one are never assumed equal.
pub fn same_build(blob: &CrashBlob, blob_image: &ImageInfo, local: &LocalImage<'_>) -> bool {
    let Some(mine) = local.image else {
        return false;
    };
    if !has_identity(blob_image) || !has_identity(&mine) {
        return false;
    }
    if !local.app_version.is_empty() && blob.app_version != local.app_version {
        return false;
    }
    if blob_image.span() != mine.span() || blob_image.build_id != mine.build_id {
        return false;
    }
    // The file size guards builds without a build id; 0 means unknown.
    blob.exe_len == 0 || local.exe_len == 0 || blob.exe_len == local.exe_len
}

/// How many bytes `backtrace::resolve` (0.3.76) steps back before lookup:
/// once in `ResolveWhat::address_or_ip`, and on the MSVC dbghelp backend a
/// second time in `resolve_with_inline`.
#[cfg(all(windows, target_env = "msvc"))]
const RESOLVE_ADJUST: u64 = 2;
#[cfg(not(all(windows, target_env = "msvc")))]
const RESOLVE_ADJUST: u64 = 1;

fn has_identity(image: &ImageInfo) -> bool {
    image.build_id.iter().any(|&b| b != 0)
}

/// Resolve the blob's frames. Frames inside the crashed main image get a
/// module offset; they are symbolicated only when this process runs the
/// same build, by re-basing the offset onto this process's image.
pub fn resolve_frames_with(
    blob: &CrashBlob,
    local: &LocalImage<'_>,
) -> (Vec<ResolvedFrame>, Symbolication) {
    let mut frames: Vec<ResolvedFrame> = blob
        .frames
        .iter()
        .map(|&ip| ResolvedFrame {
            ip,
            module_offset: blob
                .image
                .filter(|img| img.contains(ip as u64))
                .map(|img| (ip as u64).wrapping_sub(img.base)),
            symbol_name: None,
            filename: None,
            lineno: None,
        })
        .collect();

    let Some(blob_image) = blob.image else {
        let why = if blob.format_version < crate::format::VERSION {
            Symbolication::LegacyFormat
        } else {
            Symbolication::NoImage
        };
        return (frames, why);
    };
    let Some(mine) = local.image else {
        return (frames, Symbolication::NoImage);
    };
    if !has_identity(&blob_image) {
        return (frames, Symbolication::UnverifiedBuild);
    }
    if !same_build(blob, &blob_image, local) {
        return (frames, Symbolication::DifferentBuild);
    }

    for (i, frame) in frames.iter_mut().enumerate() {
        let Some(offset) = frame.module_offset else {
            continue;
        };
        // `backtrace::resolve` treats every address as a return address and
        // looks up `addr - RESOLVE_ADJUST`. Walked frames want exactly one
        // byte back (into the call instruction); frame 0 is the exact
        // faulting PC and wants none.
        let wanted_back: u64 = if i == 0 { 0 } else { 1 };
        let addr = mine
            .base
            .wrapping_add(offset)
            .wrapping_add(RESOLVE_ADJUST - wanted_back);
        backtrace::resolve(addr as usize as *mut std::ffi::c_void, |sym| {
            if frame.symbol_name.is_none() {
                frame.symbol_name = sym.name().map(|n| n.to_string());
                frame.filename = sym.filename().map(|f| f.display().to_string());
                frame.lineno = sym.lineno();
            }
        });
    }
    (frames, Symbolication::Resolved)
}

/// Resolve frames against the current process (compat entry point).
pub fn resolve_frames(blob: &CrashBlob) -> Vec<ResolvedFrame> {
    resolve_frames_with(blob, &LocalImage::current("")).0
}

/// One-line description of what happened, for the notice and the report.
pub fn describe(blob: &CrashBlob) -> String {
    let sig = signal_name(blob.signal);
    match blob.kind {
        CrashKind::Panic => {
            let thread = blob.thread_name.as_deref().unwrap_or("<unnamed>");
            let class = match blob.class {
                PanicClass::BenignBrokenPipe => " (broken pipe: output stream closed)",
                PanicClass::BenignNoSpace => " (disk full)",
                PanicClass::None => "",
            };
            format!("Rust panic on thread '{thread}'{class}")
        }
        CrashKind::StackOverflow => format!("Stack overflow ({sig})"),
        CrashKind::Signal | CrashKind::Unknown => sig.to_string(),
    }
}

/// Format a crash report as human-readable text.
pub fn format_report(blob: &CrashBlob, frames: &[ResolvedFrame]) -> String {
    format_report_with(blob, frames, None)
}

/// Format a crash report, noting how symbolication went.
pub fn format_report_with(
    blob: &CrashBlob,
    frames: &[ResolvedFrame],
    symbolication: Option<Symbolication>,
) -> String {
    let mut out = String::with_capacity(4096);

    out.push_str("=== Fuigo Crash Report ===\n\n");
    out.push_str(
        "This report was written on this computer and has not been uploaded anywhere.\n\n",
    );

    out.push_str(&format!("What:    {}\n", describe(blob)));
    out.push_str(&format!("Signal:  {}\n", signal_name(blob.signal)));
    out.push_str(&format!(
        "si_code: {} ({})\n",
        blob.si_code,
        si_code_name(blob.signal, blob.si_code)
    ));
    out.push_str(&format!("Address: {:#018x}\n", blob.si_addr));
    out.push_str(&format!("PID:     {}\n", blob.pid));
    out.push_str(&format!("Version: {}\n", blob.app_version));
    out.push_str(&format!("Time:    {} (unix)\n", blob.timestamp));
    out.push_str(&format!("Format:  v{}\n", blob.format_version));
    if let Some(img) = blob.image {
        let id: String = img.build_id.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!(
            "Image:   base {:#x}, size {:#x}, build id {id}\n",
            img.base,
            img.span()
        ));
    }
    let note = match symbolication {
        Some(Symbolication::Resolved) => {
            "symbolicated against this build (offsets re-based for ASLR)"
        }
        Some(Symbolication::DifferentBuild) => {
            "not symbolicated: the crash came from a different build; offsets are relative to that fuigo binary"
        }
        Some(Symbolication::UnverifiedBuild) => {
            "not symbolicated: the crashed binary's identity is unknown; offsets are relative to that fuigo binary"
        }
        Some(Symbolication::LegacyFormat) => {
            "not symbolicated: old report format with absolute addresses only"
        }
        Some(Symbolication::NoImage) => "not symbolicated: the program image could not be located",
        None => "",
    };
    if !note.is_empty() {
        out.push_str(&format!("Symbols: {note}\n"));
    }

    out.push_str(&format!("\nBacktrace ({} frames):\n", frames.len()));
    for (i, frame) in frames.iter().enumerate() {
        let name = frame.symbol_name.as_deref().unwrap_or("<unknown>");
        match frame.module_offset {
            Some(off) => out.push_str(&format!("  {i:>3}: fuigo+{off:#x} - {name}\n")),
            None => out.push_str(&format!("  {i:>3}: {:#018x} - {name}\n", frame.ip)),
        }
        if let (Some(file), Some(line)) = (&frame.filename, frame.lineno) {
            out.push_str(&format!("           at {}:{}\n", file, line));
        }
    }

    out.push_str("\n=== End Report ===\n");
    out
}

pub fn signal_name(sig: u8) -> &'static str {
    match sig as i32 {
        4 => "SIGILL (Illegal instruction)",
        // SIGABRT is 6 on both macOS and Linux.
        // With panic = "abort", every Rust panic terminates via SIGABRT.
        6 => "SIGABRT (Abort)",
        // SIGBUS is 10 on macOS, 7 on Linux
        7 | 10 => "SIGBUS (Bus error)",
        11 => "SIGSEGV (Segmentation fault)",
        _ => "Unknown signal",
    }
}

fn si_code_name(sig: u8, code: i32) -> &'static str {
    // SIGABRT carries no fault-specific si_code (abort(3) raises it directly;
    // the kernel reports SI_USER/SI_TKILL-style origins instead).
    if sig == 6 {
        return "abort() - raised by the process (e.g. Rust panic with panic=abort)";
    }
    let is_bus = sig == 7 || sig == 10;
    if is_bus {
        match code {
            1 => "BUS_ADRALN - invalid address alignment",
            2 => "BUS_ADRERR - non-existent physical address",
            3 => "BUS_OBJERR - object-specific hardware error",
            _ => "unknown",
        }
    } else {
        match code {
            1 => "SEGV_MAPERR - address not mapped",
            2 => "SEGV_ACCERR - invalid permissions",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::BUILD_ID_LEN;

    fn blob_v2(frames: Vec<usize>, image: Option<ImageInfo>) -> CrashBlob {
        CrashBlob {
            format_version: crate::format::VERSION,
            signal: 11,
            si_code: 1,
            si_addr: 0x10,
            pid: 42,
            timestamp: 1_712_678_587,
            frames,
            app_version: "1.0.21".to_string(),
            kind: CrashKind::Signal,
            class: PanicClass::None,
            image,
            exe_len: 100,
            start_token: 1,
            thread_name: None,
        }
    }

    #[test]
    fn signal_names() {
        assert_eq!(signal_name(6), "SIGABRT (Abort)");
        assert_eq!(signal_name(10), "SIGBUS (Bus error)");
        assert_eq!(signal_name(7), "SIGBUS (Bus error)");
        assert_eq!(signal_name(11), "SIGSEGV (Segmentation fault)");
    }

    #[test]
    fn format_report_smoke() {
        let mut blob = blob_v2(vec![0xdead_beef], None);
        blob.signal = 10;
        blob.si_code = 2;
        let frames = vec![ResolvedFrame {
            ip: 0xdead_beef,
            module_offset: None,
            symbol_name: Some("fuigo_pager::main".to_string()),
            filename: Some("src/main.rs".to_string()),
            lineno: Some(42),
        }];
        let report = format_report(&blob, &frames);
        assert!(report.contains("SIGBUS"));
        assert!(report.contains("BUS_ADRERR"));
        assert!(report.contains("fuigo_pager::main"));
        assert!(report.contains("src/main.rs:42"));
        assert!(report.contains("has not been uploaded"));
    }

    #[test]
    fn different_build_keeps_offsets_and_resolves_nothing() {
        let img = ImageInfo {
            base: 0x1000_0000,
            lo: 0x1000_0000,
            hi: 0x1100_0000,
            build_id: [9; BUILD_ID_LEN],
        };
        let blob = blob_v2(vec![0x1000_1234, 0x7fff_0000_0000], Some(img));
        let local = LocalImage {
            image: Some(ImageInfo {
                build_id: [8; BUILD_ID_LEN],
                ..img
            }),
            exe_len: 100,
            app_version: "",
        };
        let (frames, why) = resolve_frames_with(&blob, &local);
        assert_eq!(why, Symbolication::DifferentBuild);
        assert_eq!(frames[0].module_offset, Some(0x1234));
        assert_eq!(frames[1].module_offset, None, "outside the image");
        assert!(frames.iter().all(|f| f.symbol_name.is_none()));
        let text = format_report_with(&blob, &frames, Some(why));
        assert!(text.contains("fuigo+0x1234"), "{text}");
        assert!(text.contains("different build"), "{text}");
    }

    #[test]
    fn identity_checks() {
        let img = ImageInfo {
            base: 0,
            lo: 0x1000,
            hi: 0x9000,
            build_id: [1; BUILD_ID_LEN],
        };
        let blob = blob_v2(vec![], Some(img));
        let mut local = LocalImage {
            image: Some(ImageInfo {
                base: 0x5000_0000,
                lo: 0x5000_1000,
                hi: 0x5000_9000,
                ..img
            }),
            exe_len: 100,
            app_version: "1.0.21",
        };
        assert!(
            same_build(&blob, &img, &local),
            "only the load address differs"
        );
        local.app_version = "1.0.22";
        assert!(!same_build(&blob, &img, &local), "version differs");
        local.app_version = "";
        local.exe_len = 101;
        assert!(!same_build(&blob, &img, &local), "file size differs");
        local.exe_len = 100;
        let good = local.image.unwrap();
        local.image = Some(ImageInfo {
            hi: 0x5000_a000,
            ..good
        });
        assert!(!same_build(&blob, &img, &local), "image span differs");
        // Unknown identity on both sides: equal sizes and versions prove nothing.
        let anon = ImageInfo {
            build_id: [0; BUILD_ID_LEN],
            ..img
        };
        local.image = Some(ImageInfo {
            build_id: [0; BUILD_ID_LEN],
            ..good
        });
        assert!(
            !same_build(&blob, &anon, &local),
            "unknown identities never match"
        );
        let anon_blob = blob_v2(vec![0x1100], Some(anon));
        let (_, why) = resolve_frames_with(&anon_blob, &local);
        assert_eq!(why, Symbolication::UnverifiedBuild);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[inline(never)]
    fn p05a_boundary_marker_a() -> u32 {
        std::hint::black_box(1)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[inline(never)]
    fn p05a_boundary_marker_b() -> u32 {
        std::hint::black_box(2)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    /// A same-build blob whose frames are this process's own addresses.
    fn local_blob(frames: Vec<usize>) -> (CrashBlob, LocalImage<'static>) {
        let local = LocalImage::current("");
        let mut blob = blob_v2(frames, local.image);
        blob.exe_len = local.exe_len;
        (blob, local)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn faulting_pc_at_a_function_entry_resolves_to_that_function() {
        // Frame 0 is the exact PC. At a function's first byte, `addr - 1`
        // would be the previous function (or padding): the off-by-one shows.
        let entry = p05a_boundary_marker_b as *const () as usize;
        let (blob, local) = local_blob(vec![entry]);
        let (frames, why) = resolve_frames_with(&blob, &local);
        assert_eq!(why, Symbolication::Resolved);
        let name = frames[0].symbol_name.clone().unwrap_or_default();
        assert!(
            name.contains("p05a_boundary_marker_b"),
            "frame 0 at entry resolved to {name:?}"
        );
        let _ = p05a_boundary_marker_a();
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn return_address_resolves_to_the_calling_instruction() {
        // A return address one past a function's first byte must resolve to
        // that function (backtrace subtracts one); subtracting a second time
        // would land before the entry.
        let entry = p05a_boundary_marker_b as *const () as usize;
        let (blob, local) = local_blob(vec![entry, entry + 1]);
        let (frames, _) = resolve_frames_with(&blob, &local);
        let name = frames[1].symbol_name.clone().unwrap_or_default();
        assert!(
            name.contains("p05a_boundary_marker_b"),
            "return address resolved to {name:?}"
        );
    }

    #[test]
    fn legacy_blob_is_not_symbolicated() {
        let mut blob = blob_v2(vec![0x1234], None);
        blob.format_version = crate::format::VERSION_V1;
        let (frames, why) = resolve_frames_with(&blob, &LocalImage::current(""));
        assert_eq!(why, Symbolication::LegacyFormat);
        assert!(frames[0].symbol_name.is_none());
        assert!(frames[0].module_offset.is_none());
    }

    #[test]
    fn describes_panics_and_overflows() {
        let mut blob = blob_v2(vec![], None);
        blob.signal = 6;
        blob.kind = CrashKind::Panic;
        blob.thread_name = Some("tokio-runtime-worker".into());
        assert_eq!(
            describe(&blob),
            "Rust panic on thread 'tokio-runtime-worker'"
        );
        blob.class = PanicClass::BenignBrokenPipe;
        assert!(describe(&blob).contains("broken pipe"));
        blob.kind = CrashKind::StackOverflow;
        blob.signal = 11;
        assert!(describe(&blob).starts_with("Stack overflow"));
        blob.kind = CrashKind::Signal;
        assert_eq!(describe(&blob), "SIGSEGV (Segmentation fault)");
    }
}
