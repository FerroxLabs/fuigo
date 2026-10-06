//! Binary crash blob format ("GCRX").
//!
//! The signal handler writes this format using only `libc::write` (no allocation).
//! The startup reader parses it in normal Rust context.
//!
//! Version 2 adds what the next process needs to make the blob useful:
//! the crashing image's load base and extent (so instruction pointers can be
//! turned into module-relative offsets and re-based into the reader's own
//! address space under ASLR), an identity of the binary (so a report is only
//! symbolicated against the same build), and a small crash classification
//! written by the panic hook (kind, benign class, thread name). The free-form
//! panic message is never stored.
//!
//! Version 1 blobs (written by older builds) still parse; they carry absolute
//! addresses only and are reported without symbols.

/// Magic bytes identifying a valid crash file.
pub const MAGIC: [u8; 4] = *b"GCRX";

/// Current format version.
pub const VERSION: u8 = 2;

/// The original format: header without image/classification fields.
pub const VERSION_V1: u8 = 1;

/// Maximum backtrace frames captured in the signal handler.
pub const MAX_FRAMES: usize = 64;

/// Length of the null-padded version string field.
pub const VERSION_STRING_LEN: usize = 32;

/// Length of the null-padded thread-name field (v2).
pub const THREAD_NAME_LEN: usize = 32;

/// Length of the binary identity field (v2): a GNU build-id prefix on Linux,
/// `LC_UUID` on macOS, PE timestamp + image size on Windows; zeros = unknown.
pub const BUILD_ID_LEN: usize = 16;

/// Size of the v1 header (before the frames array).
///
/// Layout (shared prefix of every version):
/// - magic:        4 bytes
/// - version:      1 byte
/// - signal:       1 byte
/// - si_code:      4 bytes (i32, little-endian)
/// - si_addr:      8 bytes (u64, little-endian)
/// - pid:          4 bytes (u32, little-endian)
/// - timestamp:    8 bytes (u64, little-endian)
/// - n_frames:     2 bytes (u16, little-endian)
/// - app_version: 32 bytes (null-padded UTF-8)
pub const HEADER_SIZE_V1: usize = 4 + 1 + 1 + 4 + 8 + 4 + 8 + 2 + VERSION_STRING_LEN;

/// Fixed v2 header size (before the variable-length frames array).
///
/// v2 appends, after the v1 prefix:
/// - kind:         1 byte  ([`CrashKind`])
/// - class:        1 byte  ([`PanicClass`])
/// - reserved:     2 bytes
/// - image_base:   8 bytes (load bias / slide / module base of the main image)
/// - image_lo:     8 bytes (absolute start of the main image at crash time)
/// - image_hi:     8 bytes (absolute end, exclusive)
/// - build_id:    16 bytes
/// - exe_len:      8 bytes (size of the executable file, 0 = unknown)
/// - start_token:  8 bytes (OS process start time token of the crashing process)
/// - thread_name: 32 bytes (null-padded, sanitized; panics only)
pub const HEADER_SIZE: usize =
    HEADER_SIZE_V1 + 1 + 1 + 2 + 8 + 8 + 8 + BUILD_ID_LEN + 8 + 8 + THREAD_NAME_LEN;

/// Total maximum file size: header + 64 frames * 8 bytes each.
pub const MAX_FILE_SIZE: usize = HEADER_SIZE + MAX_FRAMES * 8;

/// How the process died.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashKind {
    /// A fatal signal / exception not attributed to a Rust panic.
    Signal,
    /// A Rust panic (the panic hook ran on the aborting thread before `abort`).
    Panic,
    /// A SIGSEGV/SIGBUS whose fault address sits next to the stack pointer.
    StackOverflow,
    /// Old-format blob: the kind was not recorded.
    Unknown,
}

impl CrashKind {
    pub fn to_u8(self) -> u8 {
        match self {
            CrashKind::Signal => 0,
            CrashKind::Panic => 1,
            CrashKind::StackOverflow => 2,
            CrashKind::Unknown => 255,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => CrashKind::Signal,
            1 => CrashKind::Panic,
            2 => CrashKind::StackOverflow,
            _ => CrashKind::Unknown,
        }
    }
}

/// Classification of a panic, computed in the panic hook from the panic
/// message (the message itself is never stored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanicClass {
    /// Not a panic, or nothing more specific is known.
    None,
    /// A write to a closed pipe / terminal (`Broken pipe`, `os error 32`).
    BenignBrokenPipe,
    /// The disk was full (`No space left on device`, `os error 28`).
    BenignNoSpace,
}

impl PanicClass {
    pub fn to_u8(self) -> u8 {
        match self {
            PanicClass::None => 0,
            PanicClass::BenignBrokenPipe => 1,
            PanicClass::BenignNoSpace => 2,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => PanicClass::BenignBrokenPipe,
            2 => PanicClass::BenignNoSpace,
            _ => PanicClass::None,
        }
    }

    /// User-environment noise rather than a Fuigo defect: the report is kept
    /// on disk but no "Fuigo crashed" notice is shown.
    pub fn is_benign(self) -> bool {
        !matches!(self, PanicClass::None)
    }
}

/// Extent and identity of the main executable image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageInfo {
    /// Value subtracted from an absolute address to get a module-relative
    /// offset (ELF load bias, Mach-O slide, PE module base).
    pub base: u64,
    /// Absolute start of the mapped image.
    pub lo: u64,
    /// Absolute end of the mapped image (exclusive).
    pub hi: u64,
    /// Binary identity; all zeros when unknown.
    pub build_id: [u8; BUILD_ID_LEN],
}

impl ImageInfo {
    pub fn contains(&self, addr: u64) -> bool {
        self.lo <= addr && addr < self.hi
    }

    pub fn span(&self) -> u64 {
        self.hi.saturating_sub(self.lo)
    }
}

/// Parsed crash data from a crash slot file.
#[derive(Debug, Clone)]
pub struct CrashBlob {
    /// Blob format version (1 or 2).
    pub format_version: u8,
    pub signal: u8,
    pub si_code: i32,
    pub si_addr: u64,
    pub pid: u32,
    pub timestamp: u64,
    /// Absolute instruction pointers as captured in the crashing process.
    pub frames: Vec<usize>,
    pub app_version: String,
    pub kind: CrashKind,
    pub class: PanicClass,
    /// Main image of the crashing process; `None` for v1 blobs or when the
    /// image could not be located at install time.
    pub image: Option<ImageInfo>,
    pub exe_len: u64,
    pub start_token: u64,
    pub thread_name: Option<String>,
}

fn le_u16(d: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([d[at], d[at + 1]])
}
fn le_u32(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]])
}
fn le_u64(d: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[at..at + 8]);
    u64::from_le_bytes(b)
}
fn padded_str(d: &[u8]) -> String {
    let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
    String::from_utf8_lossy(&d[..end]).into_owned()
}

impl CrashBlob {
    /// Parse a crash blob from bytes. Returns `None` if the data is invalid.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_SIZE_V1 || data[0..4] != MAGIC {
            return None;
        }
        let format_version = data[4];
        let header_size = match format_version {
            VERSION_V1 => HEADER_SIZE_V1,
            VERSION => HEADER_SIZE,
            _ => return None,
        };
        if data.len() < header_size {
            return None;
        }

        let signal = data[5];
        let si_code = le_u32(data, 6) as i32;
        let si_addr = le_u64(data, 10);
        let pid = le_u32(data, 18);
        let timestamp = le_u64(data, 22);
        let n_frames = le_u16(data, 30) as usize;
        let app_version = padded_str(&data[32..32 + VERSION_STRING_LEN]);

        if n_frames > MAX_FRAMES {
            return None;
        }
        let frames_end = header_size + n_frames * 8;
        if data.len() < frames_end {
            return None;
        }
        let frames = (0..n_frames)
            .map(|i| le_u64(data, header_size + i * 8) as usize)
            .collect();

        let mut blob = CrashBlob {
            format_version,
            signal,
            si_code,
            si_addr,
            pid,
            timestamp,
            frames,
            app_version,
            kind: CrashKind::Unknown,
            class: PanicClass::None,
            image: None,
            exe_len: 0,
            start_token: 0,
            thread_name: None,
        };

        if format_version == VERSION {
            let o = HEADER_SIZE_V1;
            blob.kind = CrashKind::from_u8(data[o]);
            blob.class = PanicClass::from_u8(data[o + 1]);
            let base = le_u64(data, o + 4);
            let lo = le_u64(data, o + 12);
            let hi = le_u64(data, o + 20);
            let mut build_id = [0u8; BUILD_ID_LEN];
            build_id.copy_from_slice(&data[o + 28..o + 28 + BUILD_ID_LEN]);
            if hi > lo {
                blob.image = Some(ImageInfo {
                    base,
                    lo,
                    hi,
                    build_id,
                });
            }
            let o2 = o + 28 + BUILD_ID_LEN;
            blob.exe_len = le_u64(data, o2);
            blob.start_token = le_u64(data, o2 + 8);
            let name = padded_str(&data[o2 + 16..o2 + 16 + THREAD_NAME_LEN]);
            if !name.is_empty() {
                blob.thread_name = Some(name);
            }
        }
        Some(blob)
    }
}

/// Header fields the signal handler fills in. Plain `Copy` data so it can be
/// assembled on the handler's stack without allocating.
#[derive(Clone, Copy)]
pub struct RawHeader<'a> {
    pub signal: u8,
    pub si_code: i32,
    pub si_addr: u64,
    pub pid: u32,
    pub timestamp: u64,
    pub n_frames: u16,
    pub app_version: &'a [u8],
    pub kind: u8,
    pub class: u8,
    pub image_base: u64,
    pub image_lo: u64,
    pub image_hi: u64,
    pub build_id: &'a [u8; BUILD_ID_LEN],
    pub exe_len: u64,
    pub start_token: u64,
    pub thread_name: &'a [u8],
}

/// Helpers for writing fields in the signal handler using raw byte copies.
/// These are used by `handler.rs` — all operations are on a pre-allocated
/// static buffer, no allocation involved.
pub mod writer {
    use super::{
        BUILD_ID_LEN, HEADER_SIZE, HEADER_SIZE_V1, MAGIC, RawHeader, THREAD_NAME_LEN, VERSION,
        VERSION_STRING_LEN,
    };

    fn put_padded(dst: &mut [u8], src: &[u8]) {
        dst.fill(0);
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src[..n]);
    }

    /// Write the v2 crash blob header into `buf`, returning the number of bytes written.
    ///
    /// # Safety
    ///
    /// Called from a signal handler. `buf` must be at least `HEADER_SIZE` bytes.
    pub unsafe fn write_header(buf: &mut [u8], h: &RawHeader<'_>) -> usize {
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = VERSION;
        buf[5] = h.signal;
        buf[6..10].copy_from_slice(&h.si_code.to_le_bytes());
        buf[10..18].copy_from_slice(&h.si_addr.to_le_bytes());
        buf[18..22].copy_from_slice(&h.pid.to_le_bytes());
        buf[22..30].copy_from_slice(&h.timestamp.to_le_bytes());
        buf[30..32].copy_from_slice(&h.n_frames.to_le_bytes());
        put_padded(&mut buf[32..32 + VERSION_STRING_LEN], h.app_version);

        let o = HEADER_SIZE_V1;
        buf[o] = h.kind;
        buf[o + 1] = h.class;
        buf[o + 2] = 0;
        buf[o + 3] = 0;
        buf[o + 4..o + 12].copy_from_slice(&h.image_base.to_le_bytes());
        buf[o + 12..o + 20].copy_from_slice(&h.image_lo.to_le_bytes());
        buf[o + 20..o + 28].copy_from_slice(&h.image_hi.to_le_bytes());
        buf[o + 28..o + 28 + BUILD_ID_LEN].copy_from_slice(h.build_id);
        let o2 = o + 28 + BUILD_ID_LEN;
        buf[o2..o2 + 8].copy_from_slice(&h.exe_len.to_le_bytes());
        buf[o2 + 8..o2 + 16].copy_from_slice(&h.start_token.to_le_bytes());
        put_padded(&mut buf[o2 + 16..o2 + 16 + THREAD_NAME_LEN], h.thread_name);
        HEADER_SIZE
    }

    /// Write a single frame pointer into `buf` at the given offset.
    /// Returns the new offset.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf[offset..offset+8]` is valid.
    pub unsafe fn write_frame(buf: &mut [u8], offset: usize, addr: usize) -> usize {
        buf[offset..offset + 8].copy_from_slice(&(addr as u64).to_le_bytes());
        offset + 8
    }

    /// Encode a version-1 blob (the pre-1.0.21 layout). Test support for the
    /// old-format path; never used by the handler.
    #[doc(hidden)]
    pub fn encode_v1(
        signal: u8,
        si_code: i32,
        si_addr: u64,
        pid: u32,
        timestamp: u64,
        app_version: &[u8],
        frames: &[usize],
    ) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE_V1 + frames.len() * 8];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = super::VERSION_V1;
        buf[5] = signal;
        buf[6..10].copy_from_slice(&si_code.to_le_bytes());
        buf[10..18].copy_from_slice(&si_addr.to_le_bytes());
        buf[18..22].copy_from_slice(&pid.to_le_bytes());
        buf[22..30].copy_from_slice(&timestamp.to_le_bytes());
        buf[30..32].copy_from_slice(&(frames.len() as u16).to_le_bytes());
        put_padded(&mut buf[32..32 + VERSION_STRING_LEN], app_version);
        for (i, f) in frames.iter().enumerate() {
            let at = HEADER_SIZE_V1 + i * 8;
            buf[at..at + 8].copy_from_slice(&(*f as u64).to_le_bytes());
        }
        buf
    }

    const _: () = assert!(HEADER_SIZE == HEADER_SIZE_V1 + 28 + BUILD_ID_LEN + 16 + THREAD_NAME_LEN);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_crash_blob_v2() {
        let mut buf = [0u8; MAX_FILE_SIZE];
        let version = b"0.1.169-alpha.2";
        let frames: &[usize] = &[0xdead_beef, 0xcafe_babe, 0x1234_5678];
        let build_id = [7u8; BUILD_ID_LEN];

        unsafe {
            let mut offset = writer::write_header(
                &mut buf,
                &RawHeader {
                    signal: 10,
                    si_code: 2,
                    si_addr: 0x7f8a_1234_0000,
                    pid: 42,
                    timestamp: 1_712_678_587,
                    n_frames: frames.len() as u16,
                    app_version: version,
                    kind: CrashKind::Panic.to_u8(),
                    class: PanicClass::BenignBrokenPipe.to_u8(),
                    image_base: 0x5555_0000_0000,
                    image_lo: 0x5555_0000_0000,
                    image_hi: 0x5555_0100_0000,
                    build_id: &build_id,
                    exe_len: 123_456,
                    start_token: 987_654,
                    thread_name: b"tokio-runtime-worker",
                },
            );
            for &frame in frames {
                offset = writer::write_frame(&mut buf, offset, frame);
            }

            let blob = CrashBlob::parse(&buf[..offset]).expect("parse should succeed");
            assert_eq!(blob.format_version, VERSION);
            assert_eq!(blob.signal, 10);
            assert_eq!(blob.si_code, 2);
            assert_eq!(blob.si_addr, 0x7f8a_1234_0000);
            assert_eq!(blob.pid, 42);
            assert_eq!(blob.timestamp, 1_712_678_587);
            assert_eq!(blob.frames, frames);
            assert_eq!(blob.app_version, "0.1.169-alpha.2");
            assert_eq!(blob.kind, CrashKind::Panic);
            assert_eq!(blob.class, PanicClass::BenignBrokenPipe);
            let image = blob.image.expect("image");
            assert_eq!(image.base, 0x5555_0000_0000);
            assert_eq!(image.span(), 0x100_0000);
            assert_eq!(image.build_id, build_id);
            assert_eq!(blob.exe_len, 123_456);
            assert_eq!(blob.start_token, 987_654);
            assert_eq!(blob.thread_name.as_deref(), Some("tokio-runtime-worker"));
        }
    }

    #[test]
    fn parses_old_v1_blob_without_image() {
        let data = writer::encode_v1(11, 1, 0x10, 77, 1_700_000_000, b"1.0.20", &[0x1000, 0x2000]);
        let blob = CrashBlob::parse(&data).expect("v1 must still parse");
        assert_eq!(blob.format_version, VERSION_V1);
        assert_eq!(blob.signal, 11);
        assert_eq!(blob.pid, 77);
        assert_eq!(blob.frames, vec![0x1000, 0x2000]);
        assert_eq!(blob.app_version, "1.0.20");
        assert_eq!(blob.kind, CrashKind::Unknown);
        assert!(blob.image.is_none());
        assert!(blob.thread_name.is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(b"NOPE");
        assert!(CrashBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_unknown_version_and_truncation() {
        let mut data = writer::encode_v1(11, 1, 0, 1, 1, b"x", &[]);
        data[4] = 9;
        assert!(CrashBlob::parse(&data).is_none());
        assert!(CrashBlob::parse(&[]).is_none());
        assert!(CrashBlob::parse(&MAGIC).is_none());
        // A v2 tag on a v1-sized buffer is truncated.
        let mut short = writer::encode_v1(11, 1, 0, 1, 1, b"x", &[]);
        short[4] = VERSION;
        assert!(CrashBlob::parse(&short).is_none());
    }
}
