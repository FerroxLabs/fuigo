//! P71: who may receive file content, decided by DESTINATION and nowhere else.
//!
//! Every upload destination falls in exactly one of three classes, decided here by
//! [`StorageDestinationClass::of_method`]:
//!
//! 1. **FluxRouter-operated storage proxy** (`IdentityDisclosure::for_destination`, the P43/P54
//!    predicate): files are sent unchanged.
//! 2. **The operator's own bucket** (`UploadMethod::Direct` GCS, `UploadMethod::S3`): files are sent
//!    unchanged. The operator chose that bucket for exactly this data.
//! 3. **Any other storage proxy**: file content is NOT sent at all. No filtering, no partial
//!    archive: the upload is skipped, local files are untouched, and the user is told on stderr
//!    (each of the two notices, [`WITHHELD_NOTICE`] and [`FEEDBACK_WITHHELD_NOTICE`], at most once
//!    per process). The fullscreen TUI hides stderr while it runs (Unix), so it prints them again
//!    when it gives the terminal back ([`replay_notices_since_last_replay`]).
//!
//! Fail closed: a proxy URL that cannot be classified (unparseable, wrong scheme, wrong host, empty)
//! is class 3.
//!
//! Why not filter: recognising a person's identity inside arbitrary archived bytes has no end
//! (nested encodings, duplicate keys, property names); nineteen audit rounds of the first
//! attempt (P71) each found another way. The destination is the only fact that is both known and
//! not attacker-controlled.
//!
//! The gate runs at the sink: it is the first statement of every public
//! [`crate::storage_client::StorageClient`] method that moves content to the proxy or names an object
//! to it for upload (`upload`, `upload_file`, `upload_stream`, `upload_multipart`,
//! `upload_bytes_signed`, `batch_upload`, `batch_upload_json`). Every proxy-bound path is built on
//! that client: the dispatchers of [`crate::gcs`], and through them the upload queue's worker, its
//! inline fallbacks, recovery of spilled items, the shell's trace, feedback, review-comment, share,
//! heap-profile and diagnostics uploads, and the pager's `fuigo trace`. So the decision is taken at
//! SEND time for the destination at send time, and a caller that holds a client and skips the
//! dispatchers is refused all the same. The Direct GCS and S3 arms of the dispatchers are class 2 by
//! construction and carry no gate. `fuigo-extra-ca/tests/upload_gate_guard.rs` pins the gate's
//! position and the public surface of the sink files.

use std::sync::{Mutex, Once};

use crate::UploadMethod;

/// The three destination classes. See the module note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageDestinationClass {
    /// Class 1: a FluxRouter-operated storage proxy.
    FluxRouterProxy,
    /// Class 2: the operator's own bucket (Direct GCS or S3).
    OperatorBucket,
    /// Class 3: any other storage proxy, or one that cannot be classified.
    ThirdPartyProxy,
}

impl StorageDestinationClass {
    /// Classify `method`. Exhaustive on purpose: a new [`UploadMethod`] variant must be classified
    /// here before the crate compiles.
    pub fn of_method(method: &UploadMethod) -> Self {
        match method {
            UploadMethod::Direct { .. } | UploadMethod::S3 { .. } => Self::OperatorBucket,
            UploadMethod::Proxy { proxy_base_url, .. } => Self::of_proxy_url(proxy_base_url),
        }
    }

    /// Classify a storage-proxy base URL: class 1 when FluxRouter-operated, class 3 otherwise
    /// (including every URL that cannot be classified).
    pub fn of_proxy_url(url: &str) -> Self {
        #[cfg(all(debug_assertions, any(test, feature = "test-loopback-operator")))]
        if test_loopback_operator(url) {
            return Self::FluxRouterProxy;
        }
        if fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(url).is_permitted() {
            Self::FluxRouterProxy
        } else {
            Self::ThirdPartyProxy
        }
    }

    /// Whether file content may be sent to this class.
    pub fn may_receive_content(self) -> bool {
        !matches!(self, Self::ThirdPartyProxy)
    }
}

/// TEST SEAM. It exists only in a build that has debug assertions (never a release-profile build,
/// which is what ships) AND is a test build: `cfg(test)`, or the `test-loopback-operator` feature,
/// which workspace crates enable from `[dev-dependencies]` only. `upload_gate_guard` pins the
/// `cfg`, the manifests, and that no profile turns debug assertions on.
///
/// The host literals `127.0.0.1` and `[::1]` (the latter is what `fuigo_test_support::loopback_ip`
/// picks where IPv4 loopback is slow) stand in for a FluxRouter-operated proxy, so the loopback
/// mocks of existing tests still receive content. Every other host, `localhost` and `127.0.0.2`
/// included, is classified by the production rule, which is how a test gets a class 3 mock on
/// loopback (`gate_testkit::RecordingEndpoint::third_party`).
#[cfg(all(debug_assertions, any(test, feature = "test-loopback-operator")))]
fn test_loopback_operator(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| {
        matches!(parsed.scheme(), "http" | "https")
            && matches!(parsed.host_str(), Some("127.0.0.1" | "[::1]"))
    })
}

/// The error an upload returns when its destination may not receive content. Nothing was sent.
/// Carried inside an `anyhow::Error`; find it with [`is_withheld`].
#[derive(Debug)]
pub struct WithheldFromDestination {
    /// What was withheld, for the message: the object path (never content).
    pub object_path: String,
}

impl std::fmt::Display for WithheldFromDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "upload of {} withheld: the storage proxy is not FluxRouter-operated, so no file content is sent to it",
            self.object_path
        )
    }
}

impl std::error::Error for WithheldFromDestination {}

/// Whether `error` (or anything in its chain) is a [`WithheldFromDestination`]. Nothing was sent,
/// and no retry can change the destination.
pub fn is_withheld(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<WithheldFromDestination>().is_some())
}

/// Which upload the gate is deciding for. It only selects the notice text, so the notice never
/// promises the user a remedy that does not exist for that upload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithheldKind {
    /// Session archives, traces, diagnostics, share bundles, heap profiles: a Direct GCS or S3
    /// `trace_upload_bucket` receives these in full.
    Traces,
    /// The one-shot `/feedback` session archive. It has no bucket alternative: it is offered only
    /// through the fallback storage proxy.
    FeedbackArchive,
}

/// The gate. `Ok(())` for classes 1 and 2; for class 3 the once-per-process notice is printed and
/// a [`WithheldFromDestination`] error is returned. For a caller that wants to know before it
/// reads or builds content (the storage client itself gates every send).
pub fn gate_upload(method: &UploadMethod, object_path: &str) -> anyhow::Result<()> {
    gate_upload_as(WithheldKind::Traces, method, object_path)
}

/// [`gate_upload`] for a caller whose notice text differs ([`WithheldKind`]).
pub fn gate_upload_as(
    kind: WithheldKind,
    method: &UploadMethod,
    object_path: &str,
) -> anyhow::Result<()> {
    gate_class(kind, StorageDestinationClass::of_method(method), object_path)
}

/// [`gate_upload`] for a caller that holds the proxy base URL rather than an [`UploadMethod`].
pub fn gate_proxy_url(proxy_base_url: &str, object_path: &str) -> anyhow::Result<()> {
    gate_class(
        WithheldKind::Traces,
        StorageDestinationClass::of_proxy_url(proxy_base_url),
        object_path,
    )
}

fn gate_class(
    kind: WithheldKind,
    class: StorageDestinationClass,
    object_path: &str,
) -> anyhow::Result<()> {
    if class.may_receive_content() {
        return Ok(());
    }
    tracing::warn!(object_path, "upload withheld: destination is not FluxRouter-operated");
    announce_once(kind);
    Err(anyhow::Error::new(WithheldFromDestination {
        object_path: object_path.to_owned(),
    }))
}

/// What the user is told for [`WithheldKind::Traces`]: what was withheld, why, and where full
/// traces can go.
pub const WITHHELD_NOTICE: &str = "Fuigo: session archives, traces, diagnostics, review comments, share bundles and heap profiles were NOT uploaded. \
The configured storage proxy is not FluxRouter-operated, and Fuigo does not send those files to a third-party proxy. \
Local files are untouched. To receive full traces, set a gs:// or s3:// trace_upload_bucket: a Direct GCS or S3 bucket receives them in full.";

/// What the user is told for [`WithheldKind::FeedbackArchive`]. It names no bucket: that archive has
/// no bucket alternative.
pub const FEEDBACK_WITHHELD_NOTICE: &str = "Fuigo: the feedback session archive was NOT uploaded. \
The configured storage proxy is not FluxRouter-operated, and Fuigo does not send session files to a third-party proxy. \
Local files are untouched.";

static TRACES_NOTICE_ONCE: Once = Once::new();
static FEEDBACK_NOTICE_ONCE: Once = Once::new();
static NOTICES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Print the notice for `kind` at most once per process (each kind once; the two texts differ).
fn announce_once(kind: WithheldKind) {
    let (once, text) = match kind {
        WithheldKind::Traces => (&TRACES_NOTICE_ONCE, WITHHELD_NOTICE),
        WithheldKind::FeedbackArchive => (&FEEDBACK_NOTICE_ONCE, FEEDBACK_WITHHELD_NOTICE),
    };
    announce_through(once, text, fuigo_tty_utils::best_effort_stderr::eprint_line);
}

/// The first call for `once` records `message` and hands it to `sink` (the process stderr in
/// production); every later call for the same `once` does nothing.
fn announce_through(once: &Once, message: &str, sink: impl FnOnce(&str)) {
    once.call_once(|| {
        record_notice(message);
        sink(message);
    });
}

/// Bumped to the number of recorded notices each time one is recorded ([`subscribe_notices`]).
static NOTICE_COUNT: std::sync::LazyLock<tokio::sync::watch::Sender<usize>> =
    std::sync::LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// Keep `message` in [`NOTICES`] and wake every [`subscribe_notices`] receiver.
fn record_notice(message: &str) {
    let recorded = match NOTICES.lock() {
        Ok(mut notices) => {
            notices.push(message.to_owned());
            notices.len()
        }
        Err(_) => return,
    };
    NOTICE_COUNT.send_replace(recorded);
}

/// P142: wakes whenever this process records a notice ([`announce_notice`], the withheld-upload notices). For a
/// host whose stderr is not the user's screen: the shared-session leader runs the agent, so its stderr is
/// `~/.fuigo/leader.log`, and it forwards each notice to an attached client instead ([`notices_from`]).
pub fn subscribe_notices() -> tokio::sync::watch::Receiver<usize> {
    NOTICE_COUNT.subscribe()
}

/// P142: the notices recorded in this process from index `cursor` on (all of them for `0`), oldest first. The caller
/// keeps its own cursor, so it is independent of [`replay_notices_since_last_replay`].
pub fn notices_from(cursor: usize) -> Vec<String> {
    NOTICES
        .lock()
        .map(|notices| notices.get(cursor..).map(<[String]>::to_vec).unwrap_or_default())
        .unwrap_or_default()
}

/// Print a one-off user notice from another crate and record it so the host can replay it once the
/// terminal is the user's again ([`replay_notices_since_last_replay`]), and so a shared-session leader can forward
/// it to the user's client ([`subscribe_notices`], P142). The caller owns the once-only decision; this does not
/// deduplicate.
pub fn announce_notice(message: &str) {
    record_notice(message);
    fuigo_tty_utils::best_effort_stderr::eprint_line(message);
}

/// How many entries of [`NOTICES`] a host has already shown again ([`replay_notices_since_last_replay`]).
static REPLAYED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Hand `sink` every notice printed since the last call (since the process started, the first time).
///
/// For a host whose stderr the user could not see when a notice was printed: the fullscreen TUI points
/// fd 2 at `/dev/null` on Unix while it owns the terminal, so a notice printed then reached nobody. The
/// host calls this once the terminal is the user's again; each notice is replayed at most once.
pub fn replay_notices_since_last_replay(mut sink: impl FnMut(&str)) {
    let notices = withheld_notices();
    let already = REPLAYED.swap(notices.len(), std::sync::atomic::Ordering::SeqCst);
    for notice in notices.iter().skip(already) {
        sink(notice);
    }
}

/// Every notice this process has printed (at most one per [`WithheldKind`]). For tests, which
/// cannot capture stderr.
pub fn withheld_notices() -> Vec<String> {
    NOTICES.lock().map(|n| n.clone()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(url: &str) -> UploadMethod {
        UploadMethod::Proxy {
            proxy_base_url: url.to_owned(),
            user_token: String::new(),
            deployment_key: None,
            alpha_test_key: None,
        }
    }

    #[test]
    fn three_classes() {
        use StorageDestinationClass::*;
        assert_eq!(StorageDestinationClass::of_method(&proxy("https://api.fluxrouter.ai/v1")), FluxRouterProxy);
        assert_eq!(
            StorageDestinationClass::of_method(&UploadMethod::Direct { service_account_key: None }),
            OperatorBucket
        );
        assert_eq!(
            StorageDestinationClass::of_method(&UploadMethod::S3 {
                bucket: "b".into(),
                region: "r".into(),
                credentials_file: None,
                credentials_content: None,
                endpoint_url: Some("https://s3.example".into()),
            }),
            OperatorBucket
        );
        for other in [
            "https://storage-proxy.example/v1",
            "http://api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            "https://fluxrouter.ai/v1",
            "http://127.0.0.2:9/v1",
            "http://localhost:9/v1",
            "not a url",
            "",
        ] {
            assert_eq!(StorageDestinationClass::of_method(&proxy(other)), ThirdPartyProxy, "{other}");
        }
    }

    #[test]
    fn gate_withholds_only_class_three() {
        assert!(gate_upload(&proxy("https://api.fluxrouter.ai/v1"), "a").is_ok());
        assert!(gate_upload(&UploadMethod::Direct { service_account_key: None }, "a").is_ok());
        let err = gate_upload(&proxy("https://third.example/v1"), "a/b.tar.gz").unwrap_err();
        assert!(is_withheld(&err));
        assert!(is_withheld(&err.context("while uploading")));
        assert!(!is_withheld(&anyhow::anyhow!("network down")));
    }

    /// Its own `Once` and its own sink, so no other test can make it pass: the sink receives the
    /// message on the first call and nothing on the next two.
    #[test]
    fn a_notice_reaches_the_sink_once_per_once() {
        let once = Once::new();
        let printed = std::cell::RefCell::new(Vec::new());
        for _ in 0..3 {
            announce_through(&once, "p71-private-notice", |line| printed.borrow_mut().push(line.to_owned()));
        }
        assert_eq!(*printed.borrow(), vec!["p71-private-notice".to_owned()]);
        assert_eq!(withheld_notices().iter().filter(|n| n.as_str() == "p71-private-notice").count(), 1);
    }

    /// The only caller of the replay in this test binary. A notice printed before a replay is handed over
    /// by that replay, exactly once; the next replay does not repeat it.
    #[test]
    fn a_replay_hands_over_each_notice_once() {
        let once = Once::new();
        announce_through(&once, "p71-replayed-notice", |_| {});
        let mut first = Vec::new();
        replay_notices_since_last_replay(|line| first.push(line.to_owned()));
        assert_eq!(first.iter().filter(|n| n.as_str() == "p71-replayed-notice").count(), 1, "{first:?}");
        let mut second = Vec::new();
        replay_notices_since_last_replay(|line| second.push(line.to_owned()));
        assert!(!second.iter().any(|n| n == "p71-replayed-notice"), "{second:?}");
    }

    /// P142: recording a notice wakes a subscriber, which finds it from its own cursor (independent of the replay).
    #[test]
    fn a_recorded_notice_wakes_subscribers_and_is_listed_from_a_cursor() {
        let mut rx = subscribe_notices();
        let before = notices_from(0).len();
        announce_notice("p142-subscribed-notice");
        assert!(rx.has_changed().unwrap(), "the subscriber is woken");
        rx.borrow_and_update();
        assert!(notices_from(before).iter().any(|n| n == "p142-subscribed-notice"));
        assert!(notices_from(usize::MAX).is_empty());
        let once = Once::new();
        announce_through(&once, "p142-subscribed-withheld", |_| {});
        assert!(rx.has_changed().unwrap(), "a withheld-upload notice wakes it too");
    }

    #[test]
    fn each_notice_is_printed_once_per_process_and_is_path_accurate() {
        for _ in 0..3 {
            let _ = gate_upload(&proxy("https://third.example/v1"), "x");
            let _ = gate_upload_as(WithheldKind::FeedbackArchive, &proxy("https://third.example/v1"), "y");
        }
        let notices = withheld_notices();
        assert_eq!(notices.iter().filter(|n| n.as_str() == WITHHELD_NOTICE).count(), 1);
        assert_eq!(notices.iter().filter(|n| n.as_str() == FEEDBACK_WITHHELD_NOTICE).count(), 1);
        assert!(WITHHELD_NOTICE.contains("NOT uploaded"));
        assert!(WITHHELD_NOTICE.contains("review comments"), "the notice must cover review-comment records");
        assert!(WITHHELD_NOTICE.contains("trace_upload_bucket") && WITHHELD_NOTICE.contains("Direct GCS or S3"));
        // The feedback archive has no bucket alternative, so its notice must not promise one.
        assert!(FEEDBACK_WITHHELD_NOTICE.contains("NOT uploaded"));
        assert!(!FEEDBACK_WITHHELD_NOTICE.to_lowercase().contains("bucket"));
        assert!(!FEEDBACK_WITHHELD_NOTICE.contains("S3"));
    }
}
