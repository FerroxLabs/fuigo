use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct Count;
static TRACK: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Count {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            BYTES.fetch_add(l.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if TRACK.load(Ordering::Relaxed) {
            BYTES.fetch_add(n, Ordering::Relaxed);
        }
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOC: Count = Count;
#[test]
fn p2_unrelated_million_element_array_is_skipped() {
    let body = format!(
        r#"{{"error":{{"type":"authentication_error","state":"token_expired","code":"key_revoked","unrelated":[{}0]}}}}"#,
        "0,".repeat(999_999)
    );
    BYTES.store(0, Ordering::Relaxed);
    TRACK.store(true, Ordering::Relaxed);
    let kind = fuigo_sampling_types::error::parse_error_type(body.as_bytes());
    let state = fuigo_sampling_types::error::parse_error_state(body.as_bytes());
    let code = fuigo_sampling_types::error::parse_error_code(body.as_bytes());
    let upstream =
        fuigo_sampling_types::error::UpstreamError::default().with_body(401, body.as_bytes());
    let display = fuigo_sampling_types::error::parse_error_bytes(body.as_bytes());
    TRACK.store(false, Ordering::Relaxed);
    assert_eq!(upstream.state.as_deref(), Some("token_expired"));
    assert!(!display.is_empty());
    assert_eq!(kind.as_deref(), Some("authentication_error"));
    assert_eq!(state.as_deref(), Some("token_expired"));
    assert!(code.is_some());
    assert!(
        BYTES.load(Ordering::Relaxed) < 65536,
        "allocated {} bytes for ignored array",
        BYTES.load(Ordering::Relaxed)
    );
}
