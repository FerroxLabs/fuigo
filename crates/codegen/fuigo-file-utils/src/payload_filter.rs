//! P149 (S14/K16, live lane C2 D2): one filter every storage upload's text passes through on its way off the machine.
//!
//! The scrubber that knows which credentials this process sent or holds lives above this crate (the shell's
//! `/feedback` archive scrub), so the process installs it once ([`install`]) and every upload primitive here applies
//! it: [`crate::gcs::upload_bytes`], [`crate::gcs::upload_bytes_signed`], [`crate::gcs::upload_file`] and the upload
//! queue's worker (which also covers artifacts spilled to disk by an earlier version and recovered at startup). Only
//! text media types are filtered (JSON, NDJSON, `text/*`, `*+json`); an image or an archive is sent as it is. Without
//! an installed filter nothing changes. No file is ever rewritten (K16): the filtered bytes are what is sent.

use std::borrow::Cow;
use std::path::Path;
use std::sync::OnceLock;

/// A text filter: the bytes as they may leave the machine.
pub type PayloadFilter = fn(Vec<u8>) -> Vec<u8>;

static FILTER: OnceLock<PayloadFilter> = OnceLock::new();

/// An archive filter: a gzipped tar with its text members filtered, or `None` to send it as it is (not a tar, or
/// nothing changed).
pub type ArchiveFilter = fn(&[u8]) -> Option<Vec<u8>>;

static ARCHIVE_FILTER: OnceLock<ArchiveFilter> = OnceLock::new();

/// Install this process's upload filter. The first installation wins; later calls are no-ops.
pub fn install(filter: PayloadFilter) {
    let _ = FILTER.set(filter);
}

/// Install this process's archive filter, applied by the upload queue to gzip artifacts (Astra r2 #2: a memory
/// archive spilled by an earlier version and recovered at startup). The first installation wins.
pub fn install_archive(filter: ArchiveFilter) {
    let _ = ARCHIVE_FILTER.set(filter);
}

/// Whether an upload's media type is a gzip archive.
pub fn is_gzip(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(essence.as_str(), "application/gzip" | "application/x-gzip" | "application/x-tar+gzip" | "application/x-gtar")
}

/// Whether a filter is installed.
pub fn is_installed() -> bool {
    FILTER.get().is_some()
}

/// Whether an upload's media type is text the filter reads (`application/json`, NDJSON, `text/*`, `*+json`).
pub fn is_text(content_type: &str) -> bool {
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence.starts_with("text/")
        || essence.ends_with("+json")
        || matches!(
            essence.as_str(),
            "application/json" | "application/x-ndjson" | "application/jsonl" | "application/x-jsonlines"
        )
}

/// `content` through the installed filter when it is text; unchanged otherwise.
pub fn apply<'a>(content: &'a [u8], content_type: &str) -> Cow<'a, [u8]> {
    match FILTER.get() {
        Some(filter) if is_text(content_type) => {
            let filtered = filter(content.to_vec());
            if filtered == content {
                Cow::Borrowed(content)
            } else {
                Cow::Owned(filtered)
            }
        }
        _ => Cow::Borrowed(content),
    }
}

/// A filtered copy of a file to upload, in the system temp dir (owner-only), deleted on drop. Uploading the copy
/// keeps every routing decision the original would get (multipart above the size threshold, queue compression).
pub(crate) struct FilteredCopy(std::path::PathBuf);

impl FilteredCopy {
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for FilteredCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `path` through the filter when it is text and the filter changes it: a [`FilteredCopy`] to upload instead.
/// `None` means upload the file as it is. The file itself is never changed.
pub(crate) fn filtered_copy(path: &Path, content_type: &str) -> std::io::Result<Option<FilteredCopy>> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    // A file that is not there has nothing to leak: the upload reports its own error for it.
    let read = |path: &Path| match std::fs::read(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        other => other.map(Some),
    };
    let filtered = if FILTER.get().is_some() && is_text(content_type) {
        let Some(bytes) = read(path)? else { return Ok(None) };
        match apply(&bytes, content_type) {
            Cow::Owned(filtered) => filtered,
            Cow::Borrowed(_) => return Ok(None),
        }
    } else if let Some(archive_filter) = ARCHIVE_FILTER.get().filter(|_| is_gzip(content_type)) {
        let Some(bytes) = read(path)? else { return Ok(None) };
        match archive_filter(&bytes) {
            Some(filtered) if filtered != bytes => filtered,
            _ => return Ok(None),
        }
    } else {
        return Ok(None);
    };
    let copy = std::env::temp_dir().join(format!(
        "fuigo-upload-filtered-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&copy)?;
    let copy = FilteredCopy(copy);
    std::io::Write::write_all(&mut file, &filtered)?;
    Ok(Some(copy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_testkit::RecordingEndpoint;
    use crate::queue::{TraceExportSource, UploadQueue, UploadRetryPolicy};
    use crate::{TraceExportConfig, UploadMethod};
    use std::sync::Arc;

    const MARK: &str = "p149-filter-SYNTH-marker-0001";

    /// Stands in for the shell's scrub: replaces one synthetic marker.
    fn replace_mark(bytes: Vec<u8>) -> Vec<u8> {
        String::from_utf8_lossy(&bytes).replace(MARK, "<redacted>").into_bytes()
    }

    /// Stands in for the shell's tar.gz scrub.
    fn mark_archive(archive: &[u8]) -> Option<Vec<u8>> {
        // Only this test's synthetic archive: the filter is process-wide and other tests upload gzip too.
        (archive.starts_with(&[0x1f, 0x8b]) && archive.ends_with(b"p149-archive-raw"))
            .then(|| b"p149-archive-filtered".to_vec())
    }

    fn config_for(base: String) -> TraceExportConfig {
        TraceExportConfig {
            bucket_url: None,
            service_account_key: None,
            prefix_dir: None,
            gcs_prefix: None,
            absolute_paths: false,
            archive_name_override: None,
            upload_method: UploadMethod::Proxy {
                proxy_base_url: base,
                user_token: String::new(),
                deployment_key: Some("p149-deployment-key".into()),
                alpha_test_key: None,
            },
        }
    }

    struct At(String);
    impl TraceExportSource for At {
        fn resolve(&self) -> TraceExportConfig {
            config_for(self.0.clone())
        }
    }

    /// P149 (S14/K16, Astra r1 #2): with the process's filter installed, text sent by `upload_bytes`, by
    /// `upload_file` and by the upload queue's worker (the path workspace uploads and recovered spills take) carries
    /// the filtered bytes; a binary payload is sent unchanged; the file on disk is not rewritten.
    #[tokio::test]
    async fn every_upload_primitive_and_the_queue_send_text_through_the_installed_filter() {
        install(replace_mark);
        install_archive(mark_archive);
        assert!(is_installed());
        let endpoint = RecordingEndpoint::fluxrouter_class().await;
        let config = config_for(endpoint.proxy_base_url());
        let json = format!("{{\"tool_state\":\"key {MARK}\"}}");
        crate::gcs::upload_bytes(&config, "sess/turn_0/a.json", json.as_bytes(), "application/json")
            .await
            .expect("upload_bytes");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("b.jsonl");
        std::fs::write(&file, format!("{{\"line\":\"{MARK}\"}}\n")).unwrap();
        crate::gcs::upload_file(&config, "sess/turn_0/b.jsonl", &file, "application/x-ndjson")
            .await
            .expect("upload_file");
        assert!(std::fs::read_to_string(&file).unwrap().contains(MARK), "the file on disk is unchanged");
        let image: Vec<u8> = [&[0x89u8, b'P', b'N', b'G'][..], MARK.as_bytes()].concat();
        crate::gcs::upload_bytes(&config, "sess/turn_0/c.png", &image, "image/png")
            .await
            .expect("upload image");

        let home = tempfile::tempdir().unwrap();
        let queue = UploadQueue::spawn(
            home.path(),
            Arc::new(At(endpoint.proxy_base_url())),
            UploadRetryPolicy::default(),
        );
        let _ = queue
            .enqueue_bytes_blocking(
                format!("{{\"queued\":\"{MARK}\"}}").as_bytes(),
                "sess/turn_0/tool_state.json",
                "application/json",
                "tool_state",
                "sess",
                0,
            )
            .await;
        // Astra r2 #2: a gzip artifact in the queue (a recovered memory-archive spill) goes through the archive filter.
        let raw_archive: Vec<u8> = [&[0x1fu8, 0x8b][..], b"p149-archive-raw"].concat();
        let _ = queue
            .enqueue_bytes_blocking(&raw_archive, "sess/turn_0/memory.tar.gz", "application/gzip", "memory_archive", "sess", 0)
            .await;
        queue.wait_idle(std::time::Duration::from_secs(30)).await;
        endpoint.settle(std::time::Duration::from_millis(300)).await;

        for path in ["a.json", "b.jsonl", "tool_state.json"] {
            assert!(endpoint.received_contains(path.as_bytes()), "control: {path} was uploaded");
        }
        assert!(endpoint.received_contains(&image), "a binary payload is sent unchanged");
        assert!(endpoint.received_contains(b"p149-archive-filtered"), "the queued archive went through the archive filter");
        assert!(!endpoint.received_contains(b"p149-archive-raw"), "the raw archive left the machine");
        let received = String::from_utf8_lossy(&endpoint.received()).into_owned();
        let without_image = received.replace(&String::from_utf8_lossy(&image).into_owned(), "");
        assert!(!without_image.contains(MARK), "a text upload carried the marker: {received}");
        assert_eq!(without_image.matches("<redacted>").count(), 3, "control: three text uploads filtered: {received}");
    }

    /// P149 (S14/K16, Astra r2 #2/r3 #6): a text spill recovered from an earlier run (written unfiltered) is sent
    /// through the filter by the queue worker, not as it was found.
    #[tokio::test]
    async fn a_recovered_text_spill_is_filtered_before_it_is_sent() {
        install(replace_mark);
        install_archive(mark_archive);
        let endpoint = RecordingEndpoint::fluxrouter_class().await;
        let home = tempfile::tempdir().unwrap();
        let queue = UploadQueue::spawn(
            home.path(),
            Arc::new(At(endpoint.proxy_base_url())),
            UploadRetryPolicy::default(),
        );
        let spill = home.path().join("spill.json");
        let sidecar_path = home.path().join("spill.json.meta");
        let body = format!("{{\"recovered\":\"key {MARK}\"}}");
        std::fs::write(&spill, &body).unwrap();
        let sidecar = crate::queue::QueueItemSidecar {
            schema_version: crate::queue::QUEUE_ITEM_SIDECAR_SCHEMA_VERSION,
            session_id: "sess".into(),
            turn_number: 0,
            gcs_path: "sess/turn_0/recovered.json".into(),
            content_type: "application/json".into(),
            artifact_name: "recovered".into(),
            enqueued_at: "2026-10-05T00:00:00Z".into(),
            sha256: String::new(),
        };
        assert!(matches!(
            queue.enqueue_recovered(&spill, &sidecar_path, &sidecar),
            crate::queue::EnqueueOutcome::Enqueued
        ));
        // A recovered gzip spill (a memory archive from an earlier version) goes through the archive filter, which the
        // upload primitives do not apply: only the queue's filtered copy does.
        let archive = home.path().join("spill.tar.gz");
        std::fs::write(&archive, [&[0x1fu8, 0x8b][..], b"p149-archive-raw"].concat()).unwrap();
        let archive_sidecar = crate::queue::QueueItemSidecar {
            gcs_path: "sess/turn_0/memory.tar.gz".into(),
            content_type: "application/gzip".into(),
            artifact_name: "memory_archive".into(),
            ..sidecar.clone()
        };
        assert!(matches!(
            queue.enqueue_recovered(&archive, &home.path().join("spill.tar.gz.meta"), &archive_sidecar),
            crate::queue::EnqueueOutcome::Enqueued
        ));
        queue.wait_idle(std::time::Duration::from_secs(30)).await;
        endpoint.settle(std::time::Duration::from_millis(300)).await;
        assert!(endpoint.received_contains(b"p149-archive-filtered"), "the recovered archive was filtered");
        assert!(!endpoint.received_contains(b"p149-archive-raw"), "the raw recovered archive left the machine");
        assert!(endpoint.received_contains(b"recovered.json"), "control: it was uploaded");
        assert!(endpoint.received_contains(b"<redacted>"), "the filtered copy was sent");
        assert!(!endpoint.received_contains(MARK.as_bytes()), "the recovered spill left the machine unfiltered");
    }

    /// P149 (S14/K16, Astra r3 #6): a text file the queue compresses (zstd, at upload time) is compressed from the
    /// filtered copy, so the stream the proxy receives, once decompressed, carries no marker.
    #[tokio::test]
    async fn a_compressed_queued_text_file_is_filtered_before_it_is_compressed() {
        install(replace_mark);
        let endpoint = RecordingEndpoint::fluxrouter_class().await;
        let home = tempfile::tempdir().unwrap();
        let queue = UploadQueue::spawn(
            home.path(),
            Arc::new(At(endpoint.proxy_base_url())),
            UploadRetryPolicy::default(),
        );
        let file = home.path().join("big.json");
        let body = format!("{{\"compressed\":\"key {MARK}\",\"pad\":\"{}\"}}", "x".repeat(400));
        std::fs::write(&file, &body).unwrap();
        let _ = queue
            .enqueue_file_blocking(&file, "sess/turn_0/big.json", "application/json", "big", "sess", 0, true)
            .await;
        queue.wait_idle(std::time::Duration::from_secs(30)).await;
        endpoint.settle(std::time::Duration::from_millis(300)).await;
        let received = endpoint.received();
        let start = received
            .windows(4)
            .position(|w| w == [0x28, 0xb5, 0x2f, 0xfd])
            .expect("control: a zstd stream was uploaded");
        let mut decoder = zstd::stream::read::Decoder::new(&received[start..]).unwrap();
        let mut text = Vec::new();
        let _ = std::io::Read::read_to_end(&mut decoder, &mut text);
        let text = String::from_utf8_lossy(&text);
        assert!(text.contains("<redacted>") && text.contains("compressed"), "control: {text}");
        assert!(!text.contains(MARK), "the compressed upload carried the marker: {text}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), body, "the file on disk is unchanged");
    }

    /// P149: an artifact that does not exist has nothing to filter: the filter must not turn the upload's own
    /// "no such file" into a different error (the queue's retry accounting depends on it).
    #[test]
    fn a_missing_file_has_nothing_to_filter() {
        install(replace_mark);
        install_archive(mark_archive);
        let missing = std::path::Path::new("/nonexistent/p149_payload_filter_missing");
        assert!(filtered_copy(missing, "application/json").expect("not an error").is_none());
        assert!(filtered_copy(missing, "application/gzip").expect("not an error").is_none());
    }
}
