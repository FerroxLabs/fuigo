//! Gate tests inject a fresh BootstrapProgress and assert only on their own per-tmpdir database state.

use super::*;
use crate::fts::META_KEY_SCHEMA_VERSION;

/// A synthetic session store: the gate tests exercise the claim lease, not the on-disk layout, so the sessions need no transcripts.
/// `list_sessions` has to report a non-zero count for the single-flight test, which asserts that exactly one of two racing gates ran the reindex.
struct FakeSource {
    sessions: Vec<IndexableSession>,
    /// Latched when a gate task returns.
    /// `list_sessions` runs only in the gate that won the claim, so waiting on this holds the lease until the other gate finishes its wait window.
    /// Without it the fake enumerates so fast that the loser's first claim can land after the winner already released.
    /// A launch's first claim always reindexes, so both gates would run the reindex.
    peer_done: Option<Arc<AtomicBool>>,
    /// A sibling cache file to quarantine and recreate while the claimant enumerates, i.e. inside its reindex.
    /// Stands in for a sibling test healing its own cache in the shared test process.
    heal_during_enumeration: Option<PathBuf>,
}

/// Bounds the hold in [`FakeSource::list_sessions`] so a bug cannot hang CI.
const PEER_DONE_TIMEOUT: Duration = Duration::from_secs(10);

impl FakeSource {
    fn empty() -> Self {
        Self {
            sessions: Vec::new(),
            peer_done: None,
            heal_during_enumeration: None,
        }
    }

    fn with_ids(ids: &[&str], peer_done: Arc<AtomicBool>) -> Self {
        Self {
            sessions: ids
                .iter()
                .map(|id| IndexableSession {
                    session_id: (*id).to_string(),
                    cwd: "/ws".to_string(),
                    updated_at_unix: 1_700_000_000,
                    title: format!("session {id}"),
                    updates_path: None,
                })
                .collect(),
            peer_done: Some(peer_done),
            heal_during_enumeration: None,
        }
    }
}

/// Quarantine and recreate the cache at `db_path`, as the index layer does on a corrupt file.
fn heal_cache(db_path: &Path) {
    recovery::heal_unusable(
        db_path,
        &rusqlite::Error::QueryReturnedNoRows,
        |_| Ok(false),
        |p| SessionSearchIndex::open_or_create(p).map(|_| ()),
    );
}

#[async_trait::async_trait]
impl SessionSource for FakeSource {
    async fn list_sessions(&self) -> io::Result<Vec<IndexableSession>> {
        if let Some(sibling) = &self.heal_during_enumeration {
            heal_cache(sibling);
        }
        if let Some(peer_done) = &self.peer_done {
            let deadline = Instant::now() + PEER_DONE_TIMEOUT;
            while !peer_done.load(Ordering::Acquire) && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok(self.sessions.clone())
    }

    async fn load_session(
        &self,
        session_id: &str,
        _cwd: &str,
    ) -> io::Result<Option<IndexableSession>> {
        Ok(self
            .sessions
            .iter()
            .find(|s| s.session_id == session_id)
            .cloned())
    }
}

fn no_content(_path: &Path) -> io::Result<(String, u64)> {
    Ok((String::new(), 0))
}

fn write_last_bootstrap_at(db_path: &Path) -> io::Result<()> {
    let now = chrono::Utc::now().timestamp();
    with_search_index(db_path, |index| {
        index.set_meta(META_KEY_LAST_BOOTSTRAP, &now.to_string())
    })
}

const TEST_TIMING: BootstrapTiming = BootstrapTiming {
    lease: Duration::from_secs(300),
    refresh: Duration::from_millis(50),
    peer_wait: Duration::from_millis(200),
    poll: Duration::from_millis(10),
};
const _: () = assert!(TEST_TIMING.refresh.as_millis() < TEST_TIMING.lease.as_millis());
const _: () = assert!(TEST_TIMING.poll.as_millis() < TEST_TIMING.peer_wait.as_millis());

/// [`TEST_TIMING`] with a shorter peer wait, for the single-flight test.
/// That test holds the winning gate's claim open for the losing gate's whole wait, so the shorter the wait, the shorter the test.
const CONTENDED_TIMING: BootstrapTiming = BootstrapTiming {
    lease: Duration::from_secs(300),
    refresh: Duration::from_millis(50),
    peer_wait: Duration::from_millis(60),
    poll: Duration::from_millis(5),
};
const _: () = assert!(CONTENDED_TIMING.refresh.as_millis() < CONTENDED_TIMING.lease.as_millis());
const _: () = assert!(CONTENDED_TIMING.poll.as_millis() < CONTENDED_TIMING.peer_wait.as_millis());

fn stamp_marker(db_path: &Path, value: &str) {
    with_search_index(db_path, |index| {
        index.set_meta(META_KEY_LAST_BOOTSTRAP, value)
    })
    .unwrap();
}

fn read_marker(db_path: &Path) -> Option<String> {
    with_search_index(db_path, |index| index.get_meta(META_KEY_LAST_BOOTSTRAP)).unwrap()
}

#[tokio::test]
async fn test_claimant_reindexes_even_when_marker_exists() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());
    stamp_marker(&db_path, "123");

    let source = FakeSource::empty();
    let outcome = bootstrap_with_lease_inner(
        tmp.path(),
        &source,
        no_content,
        &Arc::new(BootstrapProgress::default()),
        &TEST_TIMING,
        BootstrapRole::Launch,
    )
    .await
    .unwrap();

    // The reindex rewrote the marker and released the claim.
    assert_eq!(
        outcome,
        BootstrapOutcome::Done,
        "a claimant whose own cache was not replaced owes no second pass"
    );
    assert_ne!(
        read_marker(&db_path).as_deref(),
        Some("123"),
        "the claimant's reindex must rewrite the completion marker"
    );
    let claim =
        with_search_index(&db_path, |index| index.get_meta(META_KEY_BOOTSTRAP_CLAIM)).unwrap();
    assert_eq!(claim, None);
}

/// A heal of a DIFFERENT cache file while the claimant reindexes must not withhold this cache's completion marker.
/// The gate tests share one process and one cache epoch: a sibling test's heal landing inside this reindex is what made
/// `test_claimant_reindexes_even_when_marker_exists` fail at 16 threads with the marker still at its pre-reindex value.
#[tokio::test]
async fn test_claimant_keeps_marker_when_another_cache_heals_mid_reindex() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());
    stamp_marker(&db_path, "123");

    let sibling = tempfile::TempDir::new().unwrap();
    let sibling_db = search_db_path(sibling.path());
    with_search_index(&sibling_db, |_| Ok(())).unwrap();

    let source = FakeSource {
        sessions: Vec::new(),
        peer_done: None,
        heal_during_enumeration: Some(sibling_db.clone()),
    };
    let outcome = bootstrap_with_lease_inner(
        tmp.path(),
        &source,
        no_content,
        &Arc::new(BootstrapProgress::default()),
        &TEST_TIMING,
        BootstrapRole::Launch,
    )
    .await
    .unwrap();

    assert!(
        std::fs::read_dir(sibling_db.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("corrupt")),
        "the sibling cache was quarantined during the reindex"
    );
    assert_eq!(
        outcome,
        BootstrapOutcome::Done,
        "a sibling cache's heal is not this cache's heal: no second pass is owed"
    );
    assert_ne!(
        read_marker(&db_path).as_deref(),
        Some("123"),
        "the completion marker must be rewritten; a sibling cache's heal must not withhold it"
    );
    assert!(!has_bootstrap_claim(&db_path).unwrap());
}

#[tokio::test]
async fn test_has_completed_bootstrap_marker_lifecycle() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path();
    let db_path = search_db_path(root);

    assert_eq!(has_completed_bootstrap_marker(root).await, Some(false));

    write_last_bootstrap_at(&db_path).unwrap();
    assert_eq!(has_completed_bootstrap_marker(root).await, Some(true));

    // An older binary re-stamped a downgraded schema version.
    {
        let index = SessionSearchIndex::open_or_create(&db_path).unwrap();
        index.set_meta(META_KEY_SCHEMA_VERSION, "3").unwrap();
    }
    assert_eq!(
        has_completed_bootstrap_marker(root).await,
        Some(false),
        "a downgraded index must not count as bootstrapped even with a recent marker"
    );

    write_last_bootstrap_at(&db_path).unwrap();
    assert_eq!(has_completed_bootstrap_marker(root).await, Some(true));
}

#[tokio::test]
async fn test_waiter_adopts_peer_marker_without_reindexing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());

    let now = chrono::Utc::now().timestamp();
    with_search_index(&db_path, |index| {
        index.try_claim_bootstrap(now, TEST_TIMING.lease, "peer")
    })
    .unwrap();
    stamp_marker(&db_path, "123");

    let source = FakeSource::empty();
    bootstrap_with_lease_inner(
        tmp.path(),
        &source,
        no_content,
        &Arc::new(BootstrapProgress::default()),
        &TEST_TIMING,
        BootstrapRole::Launch,
    )
    .await
    .unwrap();

    assert_eq!(read_marker(&db_path).as_deref(), Some("123"));
}

#[tokio::test]
async fn test_try_bootstrap_returns_at_once_when_peer_holds_claim() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());

    let now = chrono::Utc::now().timestamp();
    with_search_index(&db_path, |index| {
        index.try_claim_bootstrap(now, TIMING.lease, "peer")
    })
    .unwrap();

    let source = FakeSource::empty();
    let started = std::time::Instant::now();
    try_bootstrap_with_lease(
        tmp.path(),
        &source,
        no_content,
        &Arc::new(BootstrapProgress::default()),
    )
    .await
    .unwrap();

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "a held claim must not block the recheck for the full peer wait"
    );
    assert_eq!(read_marker(&db_path), None, "no reindex ran");
}

#[tokio::test]
async fn test_recheck_adopts_marker_completed_after_its_probe() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());
    // A peer finished and released between the recheck's marker probe and its claim attempt: the marker exists and the lease is free
    stamp_marker(&db_path, "123");

    let source = FakeSource::empty();
    try_bootstrap_with_lease(
        tmp.path(),
        &source,
        no_content,
        &Arc::new(BootstrapProgress::default()),
    )
    .await
    .unwrap();

    assert_eq!(
        read_marker(&db_path).as_deref(),
        Some("123"),
        "the recheck must adopt the fresh marker, not reindex over it"
    );
    assert!(!has_bootstrap_claim(&db_path).unwrap());
}

#[tokio::test]
async fn test_waiter_gives_up_after_peer_wait() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());

    let now = chrono::Utc::now().timestamp();
    with_search_index(&db_path, |index| {
        index.try_claim_bootstrap(now, TEST_TIMING.lease, "peer")
    })
    .unwrap();

    let source = FakeSource::empty();
    bootstrap_with_lease_inner(
        tmp.path(),
        &source,
        no_content,
        &Arc::new(BootstrapProgress::default()),
        &TEST_TIMING,
        BootstrapRole::Launch,
    )
    .await
    .unwrap();

    assert_eq!(read_marker(&db_path), None, "no reindex ran");
}

#[test]
fn test_shared_index_reopens_after_epoch_change() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = search_db_path(tmp.path());
    let shared = SharedIndex::new();
    shared
        .with(&db_path, |index| index.set_meta("k", "v"))
        .unwrap();

    // A heal bumps the epoch and replaces the file.
    heal_cache(&db_path);

    let value = shared.with(&db_path, |index| index.get_meta("k")).unwrap();
    assert_eq!(
        value, None,
        "the connection must re-open at the new epoch, not keep the old fd"
    );
}

#[test]
fn test_clear_last_bootstrap_at() {
    let tmp = tempfile::TempDir::new().unwrap();
    let db_path = tmp.path().join("session_search.sqlite");

    write_last_bootstrap_at(&db_path).unwrap();
    assert!(try_read_last_bootstrap_at(&db_path).unwrap().is_some());

    clear_last_bootstrap_at(&db_path).unwrap();
    assert_eq!(try_read_last_bootstrap_at(&db_path).unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_gates_single_flight() {
    let tmp = tempfile::TempDir::new().unwrap();
    let root = tmp.path().to_path_buf();
    with_search_index(&search_db_path(&root), |_| Ok(())).unwrap();

    let progress_a = Arc::new(BootstrapProgress::default());
    let progress_b = Arc::new(BootstrapProgress::default());
    // Whichever gate loses the claim returns first and latches this, which releases the winner's enumeration
    let peer_done = Arc::new(AtomicBool::new(false));
    let source_a = FakeSource::with_ids(&["s1", "s2"], Arc::clone(&peer_done));
    let source_b = FakeSource::with_ids(&["s1", "s2"], Arc::clone(&peer_done));
    let root_a = root.clone();
    let root_b = root;
    let pa = Arc::clone(&progress_a);
    let pb = Arc::clone(&progress_b);
    let done_a = Arc::clone(&peer_done);
    let done_b = Arc::clone(&peer_done);
    let start = Arc::new(tokio::sync::Barrier::new(2));
    let start_a = Arc::clone(&start);
    let start_b = Arc::clone(&start);
    let (a, b) = tokio::join!(
        tokio::spawn(async move {
            start_a.wait().await;
            let result = bootstrap_with_lease_inner(
                &root_a,
                &source_a,
                no_content,
                &pa,
                &CONTENDED_TIMING,
                BootstrapRole::Launch,
            )
            .await;
            done_a.store(true, Ordering::Release);
            result
        }),
        tokio::spawn(async move {
            start_b.wait().await;
            let result = bootstrap_with_lease_inner(
                &root_b,
                &source_b,
                no_content,
                &pb,
                &CONTENDED_TIMING,
                BootstrapRole::Launch,
            )
            .await;
            done_b.store(true, Ordering::Release);
            result
        }),
    );
    let a = a.expect("gate a task panicked");
    let b = b.expect("gate b task panicked");
    assert!(a.is_ok(), "gate a: {a:?}");
    assert!(b.is_ok(), "gate b: {b:?}");

    let db_path = search_db_path(tmp.path());
    // The cache epoch is per cache file, so a sibling test healing its own cache cannot make the winner withhold this marker
    assert!(
        read_marker(&db_path).is_some(),
        "completion marker must exist after concurrent gates"
    );
    assert!(
        !has_bootstrap_claim(&db_path).unwrap(),
        "claim must be released after concurrent gates"
    );

    let a_ran = progress_a.total.load(Ordering::Relaxed) > 0;
    let b_ran = progress_b.total.load(Ordering::Relaxed) > 0;
    assert_eq!(
        usize::from(a_ran) + usize::from(b_ran),
        1,
        "exactly one gate must reindex, a_total={}, b_total={}",
        progress_a.total.load(Ordering::Relaxed),
        progress_b.total.load(Ordering::Relaxed),
    );
}

static STAMP_TEST_READS: AtomicU64 = AtomicU64::new(0);

/// Counts every transcript it reads; the file text is the searchable content.
fn counting_extract(path: &Path) -> io::Result<(String, u64)> {
    STAMP_TEST_READS.fetch_add(1, Ordering::SeqCst);
    let text = std::fs::read_to_string(path)?;
    let len = text.len() as u64;
    Ok((text, len))
}

fn transcript_source(dir: &Path, titles: &[(&str, &str)]) -> FakeSource {
    let mut source = FakeSource::empty();
    source.sessions = titles
        .iter()
        .map(|(id, title)| IndexableSession {
            session_id: (*id).to_string(),
            cwd: "/ws".to_string(),
            updated_at_unix: 1_700_000_000,
            title: (*title).to_string(),
            updates_path: Some(dir.join(format!("{id}.jsonl"))),
        })
        .collect();
    source
}

fn search_ids(db_path: &Path, query: &str) -> Vec<(String, String)> {
    with_search_index(db_path, |index| index.query(query, None, 50, 0, true))
        .unwrap()
        .results
        .into_iter()
        .map(|r| (r.session_id, r.snippet.unwrap_or_default()))
        .collect()
}

/// F3: a launch reindex skips transcripts whose length and mtime match the stamp on their row, and search results stay the same.
#[tokio::test]
async fn test_launch_reindex_skips_unchanged_transcripts() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("t");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("s1.jsonl"), "alpha bravo").unwrap();
    std::fs::write(dir.join("s2.jsonl"), "charlie delta").unwrap();
    let db_path = search_db_path(tmp.path());
    let run = |source: FakeSource| {
        let root = tmp.path().to_path_buf();
        async move {
            let before = STAMP_TEST_READS.load(Ordering::SeqCst);
            bootstrap_with_lease_inner(
                &root,
                &source,
                counting_extract,
                &Arc::new(BootstrapProgress::default()),
                &TEST_TIMING,
                BootstrapRole::Launch,
            )
            .await
            .unwrap();
            STAMP_TEST_READS.load(Ordering::SeqCst) - before
        }
    };
    let titles = [("s1", "first"), ("s2", "second")];

    assert_eq!(
        run(transcript_source(&dir, &titles)).await,
        2,
        "first launch reads both"
    );
    let queries = ["alpha", "delta", "first", "second"];
    let before: Vec<_> = queries.iter().map(|q| search_ids(&db_path, q)).collect();

    assert_eq!(
        run(transcript_source(&dir, &titles)).await,
        0,
        "an unchanged launch must not re-read any transcript"
    );
    let after: Vec<_> = queries.iter().map(|q| search_ids(&db_path, q)).collect();
    assert_eq!(
        before, after,
        "search results must be identical after a skipped reindex"
    );

    // An appended transcript and a renamed session are each re-read once
    std::fs::write(dir.join("s1.jsonl"), "alpha bravo echo").unwrap();
    let renamed = [("s1", "first"), ("s2", "renamed")];
    assert_eq!(run(transcript_source(&dir, &renamed)).await, 2);
    assert_eq!(search_ids(&db_path, "echo").len(), 1);
    assert_eq!(search_ids(&db_path, "renamed").len(), 1);
    assert!(search_ids(&db_path, "second").is_empty());

    // A row rewritten by another writer no longer matches its stamp, so it is re-extracted
    with_search_index(&db_path, |index| {
        index.upsert_doc(&crate::doc::build_session_doc(
            &transcript_source(&dir, &renamed).sessions[1],
            "stale".to_string(),
        ))
    })
    .unwrap();
    assert_eq!(run(transcript_source(&dir, &renamed)).await, 1);
    assert_eq!(search_ids(&db_path, "delta").len(), 1);
}

/// mem3 review M2: a value recorded after a session was indexed is scrubbed from that untouched session's row at the
/// next launch. Fails without the `contains_any` check in `unchanged_since_stamp`: the stamp matched, the transcript was
/// skipped, and the row kept the raw value.
#[allow(
    clippy::await_holding_lock,
    reason = "the recorded-set lock must stay held through the launch; a current-thread test runtime cannot deadlock on it"
)]
#[tokio::test]
async fn test_launch_rescrubs_untouched_row_holding_value_recorded_after_indexing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("t");
    std::fs::create_dir_all(&dir).unwrap();
    let value = concat!("Late", "Rec0rdedKq7Zt");
    std::fs::write(dir.join("s1.jsonl"), format!("alpha {value}")).unwrap();
    let db_path = search_db_path(tmp.path());
    let titles = [("s1", "first")];
    let source = transcript_source(&dir, &titles);
    let progress = Arc::new(BootstrapProgress::default());
    let run = || {
        bootstrap_with_lease_inner(
            tmp.path(),
            &source,
            plain_extract,
            &progress,
            &TEST_TIMING,
            BootstrapRole::Launch,
        )
    };
    let stored = || -> String {
        rusqlite::Connection::open(&db_path)
            .unwrap()
            .query_row(
                "SELECT content FROM session_docs WHERE session_id = 's1'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    };

    run().await.unwrap();
    assert!(
        stored().contains(value),
        "indexed before the value was recorded"
    );

    let _set = crate::at_rest_set_lock();
    fuigo_secrets::at_rest::record(value);
    run().await.unwrap();
    let content = stored();
    fuigo_secrets::at_rest::clear_for_tests();
    assert!(
        !content.contains(value) && content.contains("alpha"),
        "the untouched row must be re-extracted and scrubbed: {content}"
    );
}

/// [`counting_extract`] without the shared count, so a test using it never disturbs the skip test's read deltas.
fn plain_extract(path: &Path) -> io::Result<(String, u64)> {
    let text = std::fs::read_to_string(path)?;
    let len = text.len() as u64;
    Ok((text, len))
}
