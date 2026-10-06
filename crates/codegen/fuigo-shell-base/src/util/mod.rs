pub mod changelog;
pub mod event_id;
pub mod fuigo_home;
pub mod secure_file;
pub mod tips;
pub mod uname;
pub use fuigo_shared::clipboard;
pub use fuigo_shared::stderr::{stderr_lock, with_locked_stderr};
/// Generate a pseudo-random f64 in [0.0, 1.0).
///
/// Entropy comes entirely from `RandomState::new()`, which the OS seeds (via `getrandom`) on each call.
/// Dividing the top 53 hash bits by `2^53` stays uniform where casting a full `u64` to `f64` would collide values above `2^52`.
/// Not cryptographically secure; suitable for sampling and feature rollouts, not for security-sensitive uses.
pub fn random_f64() -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let random_state = RandomState::new();
    let mut hasher = random_state.build_hasher();
    hasher.write_u64(0x517cc1b727220a95);
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}
/// Returns `true` with probability `rate` (0.0 to 1.0).
pub fn probabilistic_sample(rate: f64) -> bool {
    random_f64() < rate
}
/// User-configured API origins: the CREDENTIAL-DELIVERY trust class.
///
/// TWO TRUST CLASSES, NOT ONE (P30)
/// These origins decide where a credential the user chose to send may be
/// attached: the session bearer ([`is_fuigo_api_bearer_url`]), `FUIGO_API_KEY`
/// ([`is_configured_api_origin`]), and where the API-key kill switch refuses a
/// key ([`is_fuigo_api_url`]). They do NOT decide identity disclosure. Whether
/// the `x-fuigo-*` identity headers (account id, tenant UUID, machine id) may go
/// to a destination is the FluxRouter-operated class, a compiled host check in
/// `fuigo_extra_ca::fluxrouter` carried as an `IdentityDisclosure`, and it must
/// never consult this set: a user may configure `https://api.openai.com/v1` or a
/// loopback gateway here, and that must buy the destination the user's credential,
/// not a cross-provider identifier. So a configured remote HTTPS gateway receives the
/// session bearer and no identity headers, by design. (Which credential depends on the
/// predicate: the session bearer never goes to loopback or cleartext even when
/// configured; `FUIGO_API_KEY` may go to a configured `http` loopback gateway.) Policy and call-site table:
/// `docs/destination-trust-policy.md`. This set used to be called "first-party";
/// that word is retired for destinations because it named both classes.
///
/// WHY THIS IS NOT A CONSTANT
/// These predicates used to hardcode `x.ai` / `*.x.ai` as "first-party". That
/// is coherent for the vendor this code was forked from and incoherent here:
/// Fuigo's credential is a FluxRouter or user-supplied key, and
/// `api.fluxrouter.ai` was *not* trusted while every `*.x.ai` host was. So the
/// session bearer could be attached to a vendor host and never to the endpoint
/// the user actually configured.
///
/// Trust now follows configuration. `x.ai` is trusted if — and only if — the
/// user pointed Fuigo at it.
///
/// WHY THIS IS A VALUE AND NOT ONLY A GLOBAL
/// The resolution logic lives on this type as methods, so a caller — the
/// config layer, a test — can resolve against ITS OWN instance. That is what
/// makes the production mapping testable: a process-wide store shared by every
/// test in a binary makes results depend on which test ran first, which is a
/// defect in its own right (see `agent::config::Config::install_trusted_api_origins`).
/// The free functions below resolve against the process-wide default instance.
///
/// FAILS CLOSED
/// A default instance is empty and every predicate returns `false`. The worst
/// case is that session-bearer auth does not engage until configuration is
/// loaded; the alternative failure direction would be attaching a credential to
/// an unvetted host. See `tests/trust_fails_closed.rs`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedApiOrigins {
    origins: Vec<String>,
}

impl TrustedApiOrigins {
    /// Empty and blank entries are dropped so an unset endpoint cannot widen trust.
    pub fn new<I: IntoIterator<Item = String>>(origins: I) -> Self {
        Self {
            origins: origins
                .into_iter()
                .map(|o| o.trim().to_owned())
                .filter(|o| !o.is_empty())
                .collect(),
        }
    }

    /// The configured origins, in configuration order.
    ///
    /// These are the endpoint strings exactly as configured, and a URL can carry
    /// more than an origin -- userinfo, a query-string token, a sensitive path.
    /// Never log them; log [`Self::recorded_trust`].
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// What this set admits, in the only form it may be recorded. See [`RecordedTrust`].
    pub fn recorded_trust(&self) -> RecordedTrust {
        RecordedTrust {
            origins: self
                .origins
                .iter()
                .filter_map(|o| credential_origin(o))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            hosts: self
                .origins
                .iter()
                .filter_map(|o| admitted_host(o))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
        }
    }

    /// True when no origin is configured — the fail-closed default.
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// Whether `url` sits on one of these configured origins.
    ///
    /// Compares scheme + host + port, deliberately NOT path. An origin is a
    /// security boundary; a configured base of `https://api.example.com` must
    /// cover `/v1/chat/completions` under it. [`matches_trusted_base_url`] is
    /// path-aware by design (it pins one exact proxy route) and is wrong here:
    /// with a root base its path check rejects every subpath.
    ///
    /// `Url::parse` resolves userinfo, so `https://good.example@attacker.example/`
    /// compares as `attacker.example`, and normalises case, IDN/punycode and the
    /// ideographic full stop. It does **not** normalise a trailing root dot, which
    /// [`normalized_host`] handles.
    fn matches_configured_origin(&self, url: &str) -> bool {
        let Ok(candidate) = reqwest::Url::parse(url) else {
            return false;
        };
        // URL userinfo is a separate credential channel, not part of our configured
        // provider credential contract. Never admit it through origin equality.
        if !candidate.username().is_empty() || candidate.password().is_some() {
            return false;
        }
        let Some(candidate_host) = normalized_host(&candidate) else {
            return false;
        };
        self.origins.iter().any(|base| {
            reqwest::Url::parse(base).is_ok_and(|trusted| {
                trusted.username().is_empty()
                    && trusted.password().is_none()
                    && candidate.scheme() == trusted.scheme()
                    && normalized_host(&trusted).is_some_and(|h| h == candidate_host)
                    && candidate.port_or_known_default() == trusted.port_or_known_default()
            })
        })
    }

    /// Host-only comparison against these origins.
    ///
    /// Scheme-agnostic by design so that credential *refusal* cannot be dodged by
    /// spelling an origin `http://`. It must never decide credential DELIVERY: the
    /// strict, https-only, loopback-refusing check is [`Self::is_fuigo_api_bearer_url`].
    /// P42 removed its last delivery uses (the `Unknown`-BYOK session gate, the subagent
    /// resolver and the kill switch's session substitution); every session delivery now asks
    /// `fuigo-shell`'s `auth::session_delivery::session_may_reach`. See
    /// `docs/destination-trust-policy.md`, "Session-token delivery: one predicate (P42)".
    fn host_matches_configured_origin(&self, url: &str) -> bool {
        let Some(host) = reqwest::Url::parse(url)
            .ok()
            .as_ref()
            .and_then(normalized_host)
        else {
            return false;
        };
        self.origins.iter().any(|base| {
            reqwest::Url::parse(base)
                .ok()
                .as_ref()
                .and_then(normalized_host)
                .is_some_and(|h| h == host)
        })
    }

    /// See [`is_fuigo_api_url`].
    pub fn is_fuigo_api_url(&self, url: &str) -> bool {
        if is_cli_chat_proxy_url(url) {
            return true;
        }
        self.host_matches_configured_origin(url)
    }

    /// See [`is_fuigo_api_bearer_url`].
    pub fn is_fuigo_api_bearer_url(&self, url: &str) -> bool {
        self.is_trusted_fuigo_https_url(url)
    }

    /// See [`is_trusted_fuigo_https_url`].
    pub fn is_trusted_fuigo_https_url(&self, url: &str) -> bool {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };
        if parsed.scheme() != "https" {
            return false;
        }
        if is_loopback_host(&parsed) {
            return false;
        }
        if is_trusted_cli_chat_proxy_url(url) {
            return true;
        }
        self.matches_configured_origin(url)
    }

    /// See [`is_configured_api_origin`].
    pub fn is_configured_api_origin(&self, url: &str) -> bool {
        configured_origin_scheme_allows(url) && self.matches_configured_origin(url)
    }
}

/// The process-wide default trust set, consulted by the free predicates.
///
/// Interior mutability is what lets a legitimate configuration reload be
/// followed (see [`TrustedOriginAuthority`]); it is not an invitation to
/// mutate, and only the two entry points below can write it.
static PROCESS_TRUSTED_API_ORIGINS: std::sync::RwLock<Option<TrustedApiOrigins>> =
    std::sync::RwLock::new(None);

/// Whether the single publishing authority has been handed out.
static TRUST_AUTHORITY_CLAIMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The sole capability to (re)publish the process-wide trust set.
///
/// THE SECURITY PROPERTY, AND WHY IT MOVED
/// The store used to be a `OnceLock`: the first *value* won and later writes
/// were ignored, so nothing running later could widen the trust set. That is
/// the property to keep — but it also froze the set at the first config load
/// while `[endpoints]` went on being re-read per turn, so a reloaded endpoint
/// became a host the session bearer and `FUIGO_API_KEY` were silently refused
/// to, and every request went out unauthenticated.
///
/// First-write-wins is therefore replaced by **first-claim-wins**, which is the
/// same property stated at the right granularity: exactly one authority exists
/// per process, [`claim_trusted_origin_authority`] hands it to the first caller
/// and to nobody afterwards, and the production claimant is the config layer at
/// startup, before any plugin, MCP server or extension code runs. Code that
/// runs later cannot obtain one, so it cannot widen the trust set. What it can
/// no longer do is leave the set stale.
pub struct TrustedOriginAuthority(());

impl TrustedOriginAuthority {
    /// Replace the process-wide trust set. Only the authority holder may call this.
    ///
    /// Every write is recorded, as a [`TrustSetChange`] of what the set admits per
    /// matcher tier (see [`RecordedTrust`]). Prevention is not available here without
    /// breaking the feature this exists to provide -- a user who edits their
    /// endpoint must have the credential follow it -- so the trade is detection: a
    /// trust set that moves leaves a record naming what moved. This emits the
    /// `tracing` event and hands the change to the installed [`TrustRecordSink`]
    /// (the application writes it to the always-on unified log, which no tracing
    /// filter can suppress); the returned change is for the caller's own use.
    pub fn publish(&self, origins: TrustedApiOrigins) -> TrustSetChange {
        let change = {
            let mut guard = PROCESS_TRUSTED_API_ORIGINS
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let change = TrustSetChange::between(guard.as_ref(), &origins);
            *guard = Some(origins);
            enqueue_trust_record(&change, TrustWritePath::Authority);
            change
        };
        // Emitted after the write lock is released: a subscriber must never run
        // while a credential check elsewhere is blocked on this lock.
        change.trace(TrustWritePath::Authority);
        drain_trust_records();
        change
    }
}

/// Receives the persistent record of every write to the process-wide trust set.
///
/// `fuigo-shell-base` cannot depend on the unified log (`fuigo-telemetry`), so the
/// record is written through a sink the application injects at startup. Both write
/// entry points deliver to it themselves, so a caller anywhere in the workspace
/// gets the persistent record without having to remember to write it.
///
/// Delivery is lossless and in the order the writes took effect: each write is
/// queued while it holds the trust-set lock, and one drainer at a time delivers the
/// queue, outside that lock. Until a sink is installed the queue simply grows (a
/// process makes a handful of writes: the seed, plus one per real movement by the
/// single authority; unchanged republishes are not queued), and it is delivered, in
/// order, by [`install_trust_record_sink`]. `record` should not panic; if it does,
/// the record it panicked on stays queued and is delivered again by the next drain.
/// A sink may call back into the trust-set writers: the nested write is queued and
/// delivered by the outer drain rather than deadlocking.
pub trait TrustRecordSink: Send + Sync {
    /// Persist one write. Never an unchanged-republish (those happen on every
    /// settings reapply and are filtered out before queueing).
    fn record(&self, change: &TrustSetChange, via: TrustWritePath);
}

#[derive(Default)]
struct TrustRecordState {
    sink: Option<std::sync::Arc<dyn TrustRecordSink>>,
    queue: std::collections::VecDeque<(TrustSetChange, TrustWritePath)>,
}

static TRUST_RECORD_STATE: std::sync::Mutex<Option<TrustRecordState>> = std::sync::Mutex::new(None);

/// Serialises delivery so records reach the sink in queue order.
static TRUST_RECORD_DRAIN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_trust_record_state<R>(f: impl FnOnce(&mut TrustRecordState) -> R) -> R {
    let mut guard = TRUST_RECORD_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(guard.get_or_insert_with(TrustRecordState::default))
}

/// Queue one write. Called while the caller still holds the trust-set write lock,
/// so queue order is mutation order. Lock order is always trust-set, then this.
fn enqueue_trust_record(change: &TrustSetChange, via: TrustWritePath) {
    if matches!(change, TrustSetChange::Unchanged { .. }) {
        return;
    }
    with_trust_record_state(|state| state.queue.push_back((change.clone(), via)));
}

/// Deliver every queued record to the sink, if one is installed. Never holds the
/// trust-set lock, so a slow sink cannot block a credential check.
fn drain_trust_records() {
    loop {
        let drain = match TRUST_RECORD_DRAIN.try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            // Another drainer (or this thread, from inside a sink) is running. It
            // re-checks the queue after releasing, so our record is not lost.
            Err(std::sync::TryLockError::WouldBlock) => return,
        };
        // Pop only after delivery, so a panicking sink does not lose the record.
        // The panic is let through after the drain lock is released; the queue
        // keeps what was not delivered and `flush_trust_records` (or the next
        // write) delivers it.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            while let Some((sink, change, via)) = with_trust_record_state(|state| {
                let sink = state.sink.clone()?;
                let (change, via) = state.queue.front().cloned()?;
                Some((sink, change, via))
            }) {
                sink.record(&change, via);
                with_trust_record_state(|state| state.queue.pop_front());
            }
        }));
        drop(drain);
        if let Err(payload) = outcome {
            std::panic::resume_unwind(payload);
        }
        let more = with_trust_record_state(|state| state.sink.is_some() && !state.queue.is_empty());
        if !more {
            return;
        }
    }
}

/// Deliver any records still queued, for an application that caught a panic from
/// its sink. Delivery is at-least-once: the record the sink panicked on is
/// delivered again. A no-op when nothing is queued or no sink is installed.
pub fn flush_trust_records() {
    drain_trust_records();
}

/// Install the persistent-record sink. First install wins; returns `false` (and
/// drops `sink`) if one is already installed. Writes made before this call are
/// delivered to `sink` here, in order.
pub fn install_trust_record_sink(sink: std::sync::Arc<dyn TrustRecordSink>) -> bool {
    // The rejected sink is handed back out of the closure so its `Drop` runs
    // after the state lock is released, not under it.
    let rejected = with_trust_record_state(|state| {
        if state.sink.is_some() {
            Some(sink)
        } else {
            state.sink = Some(sink);
            None
        }
    });
    if rejected.is_some() {
        return false;
    }
    drain_trust_records();
    true
}

/// Which entry point wrote the process-wide trust set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustWritePath {
    /// [`set_trusted_api_origins`]: first-write-wins seeding.
    Seed,
    /// [`TrustedOriginAuthority::publish`]: the config layer's reload path.
    Authority,
}

impl TrustWritePath {
    /// Stable label for log records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Authority => "authority",
        }
    }
}

/// What a trust set ADMITS, in a form that may be logged anywhere.
///
/// The set is consulted through two matchers, and they admit different things,
/// so the record carries both -- recording only one would let a real change of
/// trust compare equal:
///
/// * `origins` -- what `TrustedApiOrigins::matches_configured_origin` admits:
///   the strict, credential-bearing tier behind `is_fuigo_api_bearer_url`,
///   `is_trusted_fuigo_https_url` and `is_configured_api_origin`. One
///   `scheme://host[:port]` per configured entry that parses, has a host and
///   carries NO userinfo. An entry with userinfo admits nothing here, so it is
///   absent: `https://u:p@gw/v1` -> `https://gw/v1` is a widening (nothing ->
///   `https://gw`), not a no-op.
/// * `hosts` -- what `TrustedApiOrigins::host_matches_configured_origin` admits:
///   the scheme-agnostic tier behind `is_fuigo_api_url`. One normalized host per
///   entry that parses and has a host, userinfo or not (that matcher does not
///   refuse it).
///
/// An entry that does not parse, or has no host, admits nothing in either tier
/// and is absent from both; so is its text. Nothing a configured endpoint can
/// carry beyond scheme, host and port -- userinfo, a query-string token, a path --
/// appears. Two sets with equal records admit exactly the same URLs; the unit
/// tests assert that agreement against the matchers themselves.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RecordedTrust {
    pub origins: Vec<String>,
    pub hosts: Vec<String>,
}

impl RecordedTrust {
    /// Entries of `self` absent from `other`, per tier.
    fn minus(&self, other: &Self) -> Self {
        Self {
            origins: self
                .origins
                .iter()
                .filter(|o| !other.origins.contains(o))
                .cloned()
                .collect(),
            hosts: self
                .hosts
                .iter()
                .filter(|h| !other.hosts.contains(h))
                .cloned()
                .collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.origins.is_empty() && self.hosts.is_empty()
    }
}

/// What one write to the process-wide trust set did, as [`RecordedTrust`]s.
///
/// Never a configured endpoint string, so a record can be logged anywhere.
/// Comparison is on what the matchers admit, so a path-only edit is
/// `Unchanged` and a userinfo-only edit is `Changed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustSetChange {
    /// The first set this process installed: its baseline. Comparing the
    /// baselines of successive processes is what shows an edit made between
    /// sessions, which no in-process comparison can see.
    Initial { current: RecordedTrust },
    /// Replaced by a set that admits exactly the same URLs.
    Unchanged { current: RecordedTrust },
    /// What the set admits moved. `added` is non-empty on a widening.
    Changed {
        previous: RecordedTrust,
        current: RecordedTrust,
        added: RecordedTrust,
        removed: RecordedTrust,
    },
}

impl TrustSetChange {
    /// Describe replacing `previous` (`None`: nothing installed yet) with `next`.
    pub fn between(previous: Option<&TrustedApiOrigins>, next: &TrustedApiOrigins) -> Self {
        let current = next.recorded_trust();
        let Some(previous) = previous else {
            return Self::Initial { current };
        };
        let previous = previous.recorded_trust();
        if previous == current {
            return Self::Unchanged { current };
        }
        Self::Changed {
            added: current.minus(&previous),
            removed: previous.minus(&current),
            previous,
            current,
        }
    }

    /// True when some URL that was not admitted before, by either matcher, is
    /// admitted now.
    pub fn is_widening(&self) -> bool {
        matches!(self, Self::Changed { added, .. } if !added.is_empty())
    }

    /// Emit this change as a `tracing` event.
    ///
    /// LEVELS, chosen deliberately. A baseline is `info`; an unchanged republish
    /// is `debug` (it happens on every settings reapply); ANY movement is `warn`
    /// -- a widening because a new host may now be sent the credential, a
    /// narrowing because the removed host will now be refused it, which is how
    /// the silent-401 this set exists to prevent presents. What a default
    /// configuration shows of these is limited by the subscriber's filter (the
    /// TUI's in-app log shows `warn`; headless stderr is `off`; agent stderr is
    /// `error`), which is why the config layer ALSO writes every baseline and
    /// every movement to the unified log, which has no filter.
    pub fn trace(&self, via: TrustWritePath) {
        let via = via.as_str();
        match self {
            Self::Initial { current } => tracing::info!(
                via,
                origins = ?current,
                "trusted API origins installed (process baseline)"
            ),
            Self::Unchanged { current } => {
                tracing::debug!(via, origins = ?current, "trusted API origins republished unchanged");
            }
            Self::Changed {
                previous,
                current,
                added,
                removed,
            } => {
                if !self.is_widening() {
                    tracing::warn!(
                        via,
                        ?removed,
                        ?previous,
                        ?current,
                        "trusted API origins narrowed: the removed origins will no longer \
                         be sent the configured API credential"
                    );
                } else {
                    tracing::warn!(
                        via,
                        ?added,
                        ?removed,
                        ?previous,
                        ?current,
                        "trusted API origins WIDENED: an origin that was not previously \
                         trusted may now receive the configured API credential"
                    );
                }
            }
        }
    }
}

/// Take the process's one publishing authority. `Some` for the first caller,
/// `None` for every caller after it, forever. See [`TrustedOriginAuthority`].
pub fn claim_trusted_origin_authority() -> Option<TrustedOriginAuthority> {
    let already = TRUST_AUTHORITY_CLAIMED.swap(true, std::sync::atomic::Ordering::AcqRel);
    (!already).then_some(TrustedOriginAuthority(()))
}

/// Seed the user-configured API origins.
///
/// FIRST WRITE WINS, unchanged: ignored once a set is present, and ignored once
/// an authority has been claimed. This is the entry point for callers that only
/// need to install a set once (test fixtures, and the initial config parse);
/// following a reload requires a [`TrustedOriginAuthority`].
/// Empty and blank entries are dropped so an unset endpoint cannot widen trust.
///
/// Returns the [`TrustSetChange`] when this call installed the set (always
/// [`TrustSetChange::Initial`]) and `None` when it was inert. An installing call
/// is recorded exactly like a publish: in production this is usually the write
/// that establishes the process baseline, because the initial config parse runs
/// before the authority is claimed.
pub fn set_trusted_api_origins<I: IntoIterator<Item = String>>(
    origins: I,
) -> Option<TrustSetChange> {
    let cleaned = TrustedApiOrigins::new(origins);
    let change = {
        let mut guard = PROCESS_TRUSTED_API_ORIGINS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.is_none() && !TRUST_AUTHORITY_CLAIMED.load(std::sync::atomic::Ordering::Acquire) {
            let change = TrustSetChange::between(None, &cleaned);
            *guard = Some(cleaned);
            enqueue_trust_record(&change, TrustWritePath::Seed);
            Some(change)
        } else {
            None
        }
    };
    if let Some(change) = &change {
        change.trace(TrustWritePath::Seed);
        drain_trust_records();
    }
    change
}

/// Resolve against the process-wide set without cloning it.
///
/// The predicates below run on every request, so they borrow under the read
/// lock rather than copy the set each time. An absent set resolves against an
/// empty one, which refuses everything -- the fail-closed direction.
fn with_process_trusted_api_origins<R>(f: impl FnOnce(&TrustedApiOrigins) -> R) -> R {
    let guard = PROCESS_TRUSTED_API_ORIGINS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match guard.as_ref() {
        Some(origins) => f(origins),
        None => f(&TrustedApiOrigins::default()),
    }
}

/// The process-wide trust set. Empty (fails closed) until one is installed.
pub fn process_trusted_api_origins() -> TrustedApiOrigins {
    PROCESS_TRUSTED_API_ORIGINS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .unwrap_or_default()
}

/// The user-configured API origins. Empty until [`set_trusted_api_origins`].
pub fn trusted_api_origins() -> Vec<String> {
    process_trusted_api_origins().origins
}

/// A host with the DNS root dot removed.
///
/// `https://host./v1` and `https://host/v1` reach the same server -- a trailing
/// dot is a fully-qualified name -- but `Url::parse` keeps it in `host_str`,
/// so a bare string comparison treats them as different origins. That is not
/// cosmetic: `is_fuigo_api_url` gates `enforce_disable_api_key_auth`, the
/// enterprise "force session auth" kill switch, so a trailing dot in a
/// `base_url` would evade a policy documented to fail closed.
fn normalized_host(url: &reqwest::Url) -> Option<String> {
    url.host_str().map(|h| h.trim_end_matches('.').to_owned())
}

/// The origin a configured entry makes trusted to the STRICT matcher
/// (`TrustedApiOrigins::matches_configured_origin`), as `scheme://host[:port]`.
///
/// Mirrors that matcher exactly: the entry must parse, carry no userinfo and
/// have a host; it then matches on scheme, normalized host (case, IDN, trailing
/// root dot) and port-or-scheme-default. `Url::port` is `None` exactly when the
/// port is the scheme default, so the rendering is equal iff the matcher's key
/// is. `None` means the entry admits nothing in this tier.
fn credential_origin(entry: &str) -> Option<String> {
    let url = reqwest::Url::parse(entry).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = normalized_host(&url)?;
    Some(match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    })
}

/// The host a configured entry makes trusted to the HOST-ONLY matcher
/// (`TrustedApiOrigins::host_matches_configured_origin`). Mirrors it exactly:
/// any entry that parses and has a host, userinfo or not. `None` means the entry
/// admits nothing in this tier.
fn admitted_host(entry: &str) -> Option<String> {
    let url = reqwest::Url::parse(entry).ok()?;
    normalized_host(&url)
}

fn matches_trusted_base_url(candidate: &str, trusted_base: &str) -> bool {
    let Ok(candidate) = reqwest::Url::parse(candidate) else {
        return false;
    };
    let Ok(trusted) = reqwest::Url::parse(trusted_base) else {
        return false;
    };
    let trusted_path = trusted.path();
    let candidate_path = candidate.path();
    let path_matches = candidate_path == trusted_path
        || candidate_path
            .strip_prefix(trusted_path)
            .is_some_and(|suffix| suffix.starts_with('/'));
    candidate.scheme() == trusted.scheme()
        && candidate.host_str() == trusted.host_str()
        && candidate.port_or_known_default() == trusted.port_or_known_default()
        && path_matches
}
/// Production cli-chat-proxy base only (compiled-in constant).
///
/// Unlike [`is_cli_chat_proxy_url`], this rejects loopback and staging/dev hosts.
/// Used for security-sensitive remote kill-switches.
/// Those must not become env toggles via `FUIGO_CLI_CHAT_PROXY_BASE_URL` (or similar) pointing at an attacker-controlled origin.
pub fn is_prod_cli_chat_proxy_url(url: &str) -> bool {
    matches_trusted_base_url(url, crate::env::PROD_CLI_CHAT_PROXY_BASE_URL)
}
/// True for the compiled cli-chat-proxy route, excluding arbitrary loopback URLs.
///
/// Unlike [`is_cli_chat_proxy_url`], this only trusts the exact compiled or environment-selected route.
/// It is suitable for Ferrox Labs-only request extensions.
pub fn is_trusted_cli_chat_proxy_url(url: &str) -> bool {
    if is_prod_cli_chat_proxy_url(url) {
        return true;
    }
    false
}
/// True for cli-chat-proxy URLs (production, plus local-dev hosts when the optional non-production feature is enabled).
/// When that feature is on, runtime env overrides can extend this trust set.
/// Loopback is always accepted (unit tests and local mock servers on arbitrary ports).
pub fn is_cli_chat_proxy_url(url: &str) -> bool {
    if is_trusted_cli_chat_proxy_url(url) {
        return true;
    }
    reqwest::Url::parse(url).is_ok_and(|u| is_canonical_loopback_host(&u))
}
/// True when `url`'s host is exactly `localhost`, `127.0.0.1` or `::1`.
///
/// Compares the parsed host, not `host_str()`: for an IPv6 literal `host_str()` is the bracketed `[::1]`,
/// so a string match against `"::1"` can never succeed.
pub fn is_canonical_loopback_host(url: &reqwest::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip == std::net::Ipv4Addr::LOCALHOST,
        Some(url::Host::Ipv6(ip)) => ip == std::net::Ipv6Addr::LOCALHOST,
        None => false,
    }
}
/// True only for hosts the user actually configured (see
/// [`set_trusted_api_origins`]), and -- unless that host is loopback -- only
/// over `https`.
///
/// The narrow sibling of [`is_fuigo_api_url`], and the first difference is
/// loopback. `is_fuigo_api_url` grants **any** `localhost` / `127.0.0.1` /
/// `::1` URL unconditionally, which is right for its job -- it gates a
/// *refusal* (`disable_api_key_auth`) and is used by unit tests and local mock
/// servers -- but wrong for deciding where a credential may be *sent*. A models
/// catalogue that named `http://localhost:9999/v1` would otherwise collect the
/// user's `FUIGO_API_KEY` from any local listener. Loopback is accepted here
/// only when it is itself one of the configured origins.
///
/// The second difference is the scheme. A configured *remote* host must be
/// reached over `https`: plaintext to another machine puts `FUIGO_API_KEY` on
/// the wire, and it is a downgrade the user never asked for even when they did
/// choose the host. A configured *loopback* origin may use HTTP, so
/// someone running their own gateway on `http://localhost:8080/v1` -- an
/// endpoint they configured deliberately, on traffic that never leaves the
/// machine -- keeps working.
///
/// Scheme, normalized host and effective port must all match the configured
/// origin. Choosing localhost:8080 does not authorize localhost:9999 or an
/// HTTPS listener on that port. URL userinfo is rejected on both sides.
pub fn is_configured_api_origin(url: &str) -> bool {
    with_process_trusted_api_origins(|origins| origins.is_configured_api_origin(url))
}

/// The scheme half of [`is_configured_api_origin`], split out so the loopback
/// carve-out is testable on its own: it consults no origins at all, so it can
/// be asserted without installing any.
///
/// Consults no configuration: `https` passes anywhere, `http` passes on a
/// loopback host, everything else fails. An unparseable URL fails.
fn configured_origin_scheme_allows(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| {
        parsed.scheme() == "https" || (parsed.scheme() == "http" && is_loopback_host(&parsed))
    })
}

/// True for the user-CONFIGURED API endpoints (see
/// [`set_trusted_api_origins`]) plus the compiled cli-chat-proxy route.
/// No vendor is privileged by compilation.
/// `disable_api_key_auth` refuses keys only for these; other hosts are BYOK and exempt.
/// Safe against invalid URLs and suffix attacks (`evil-x.ai.example`).
///
/// Scheme-agnostic so credential *refusal* fails closed.
/// To decide where to *attach* a credential, use [`is_fuigo_api_bearer_url`].
pub fn is_fuigo_api_url(url: &str) -> bool {
    with_process_trusted_api_origins(|origins| origins.is_fuigo_api_url(url))
}
/// Like [`is_fuigo_api_url`], but requires `https` on every arm, so a session bearer is never attached to a cleartext endpoint, including loopback.
/// A co-located process could otherwise read a token sent to `http://localhost`.
pub fn is_fuigo_api_bearer_url(url: &str) -> bool {
    with_process_trusted_api_origins(|origins| origins.is_fuigo_api_bearer_url(url))
}
/// True for user-configured HTTPS API origins (and the compiled cli-chat-proxy route), excluding
/// arbitrary loopback URLs. Credential delivery, not identity disclosure: see [`TrustedApiOrigins`].
pub fn is_trusted_fuigo_https_url(url: &str) -> bool {
    with_process_trusted_api_origins(|origins| origins.is_trusted_fuigo_https_url(url))
}
fn is_loopback_host(parsed: &reqwest::Url) -> bool {
    match parsed.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}
/// Truncate a string to at most `max_chars` characters.
/// Slices at char boundaries so multi-byte UTF-8 never panics.
pub fn truncate(s: &str, max_chars: usize) -> &str {
    if s.len() <= max_chars {
        return s;
    }
    let end = s
        .char_indices()
        .nth(max_chars)
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}
/// Check if a process is still alive.
///
/// - Unix: `kill(pid, 0)` via `nix`. True if the process exists (even under a different UID); false only on ESRCH.
/// - Windows: `OpenProcess(SYNCHRONIZE)` then `WaitForSingleObject(0)`. True while running; false on exit, absence, or open failure.
#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    match kill(Pid::from_raw(pid as i32), None) {
        Ok(()) => true,
        Err(Errno::ESRCH) => false,
        Err(_) => true,
    }
}
#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else {
        return false;
    };
    let wait_result = unsafe { WaitForSingleObject(handle, 0) };
    let _ = unsafe { CloseHandle(handle) };
    wait_result == WAIT_TIMEOUT
}
/// Which termination signal to send.
/// On Windows both map to `TerminateProcess` (already forceful), so the distinction only matters on Unix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSignal {
    /// Graceful `SIGTERM` (Unix); the process may catch and drain.
    Term,
    /// Forceful `SIGKILL` (Unix); the process cannot catch or block it.
    Kill,
}
/// Terminate a process by PID with `SIGTERM`. Idempotent: already-dead is `Ok`.
pub fn kill_process_by_pid(pid: u32) -> std::io::Result<()> {
    kill_process_with_signal(pid, KillSignal::Term)
}
/// Terminate a process by PID with a chosen signal. Idempotent: already-dead is `Ok`.
///
/// - Unix: `SIGTERM`/`SIGKILL` via `nix::sys::signal::kill`; ESRCH maps to `Ok`.
/// - Windows: `OpenProcess(PROCESS_TERMINATE)` then `TerminateProcess`; ERROR_INVALID_PARAMETER maps to `Ok`.
///   `TerminateProcess` is already forceful, so `signal` is ignored.
pub fn kill_process_with_signal(pid: u32, signal: KillSignal) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        use nix::sys::signal::{Signal, kill};
        use nix::unistd::Pid;
        let sig = match signal {
            KillSignal::Term => Signal::SIGTERM,
            KillSignal::Kill => Signal::SIGKILL,
        };
        match kill(Pid::from_raw(pid as i32), sig) {
            Ok(()) | Err(Errno::ESRCH) => Ok(()),
            Err(e) => Err(std::io::Error::from_raw_os_error(e as i32)),
        }
    }
    #[cfg(windows)]
    {
        let _ = signal;
        use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER};
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
        use windows::core::HRESULT;
        let no_such_process = HRESULT::from_win32(ERROR_INVALID_PARAMETER.0);
        let handle = match unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) } {
            Ok(h) => h,
            Err(e) if e.code() == no_such_process => return Ok(()),
            Err(e) => {
                return Err(std::io::Error::other(format!("OpenProcess({pid}): {e}")));
            }
        };
        let terminate = unsafe { TerminateProcess(handle, 0) };
        let _ = unsafe { CloseHandle(handle) };
        terminate.map_err(|e| std::io::Error::other(format!("TerminateProcess({pid}): {e}")))
    }
}
/// Command-line arguments of `pid`. Exact on Linux (/proc); approximate on
/// macOS/BSD (`ps`, whitespace-split — fine for flag lookups); `None` on
/// Windows or when the process is gone.
pub fn process_cmdline_args(pid: u32) -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        let data = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let args: Vec<String> = data
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        (!args.is_empty()).then_some(args)
    }
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        let mut cmd = std::process::Command::new("ps");
        cmd.args(["-o", "args=", "-p", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        fuigo_tty_utils::detach_std_command(&mut cmd);
        let output = cmd.output().ok()?;
        if !output.status.success() {
            return None;
        }
        let args: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        (!args.is_empty()).then_some(args)
    }
    #[cfg(windows)]
    {
        let _ = pid;
        None
    }
}
/// True if `pid` is a fuigo process; pairs with [`kill_process_by_pid`] to avoid killing a recycled PID.
/// Best-effort on macOS/BSD (liveness-only via `kill -0`), exact on Linux (/proc cmdline) and Windows (image path).
pub fn is_fuigo_process(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let cmdline_path = format!("/proc/{pid}/cmdline");
        match std::fs::read(&cmdline_path) {
            Ok(data) => String::from_utf8_lossy(&data).contains("fuigo"),
            Err(_) => false,
        }
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        };
        use windows::core::PWSTR;
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return false;
        };
        let mut buf: Vec<u16> = vec![0; 1024];
        let mut size: u32 = buf.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
        };
        let _ = unsafe { CloseHandle(handle) };
        if result.is_err() {
            return false;
        }
        String::from_utf16_lossy(&buf[..size as usize])
            .to_ascii_lowercase()
            .contains("fuigo")
    }
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        let mut cmd = std::process::Command::new("kill");
        cmd.args(["-0", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        fuigo_tty_utils::detach_std_command(&mut cmd);
        cmd.status().is_ok_and(|s| s.success())
    }
}
/// Stricter [`is_fuigo_process`] for the path that auto-kills zombie leaders.
/// On macOS/BSD it matches the name via `ps` instead of liveness-only, so it never SIGKILLs a recycled PID now owned by an unrelated process.
/// Linux/Windows already match exactly, so this delegates there.
/// Use the permissive [`is_fuigo_process`] for operator-driven `fuigo leaders kill`.
pub fn is_fuigo_process_strict(pid: u32) -> bool {
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        let mut cmd = std::process::Command::new("ps");
        cmd.args(["-p", &pid.to_string(), "-o", "comm="])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        fuigo_tty_utils::detach_std_command(&mut cmd);
        match cmd.output() {
            Ok(out) if out.status.success() => {
                let comm = String::from_utf8_lossy(&out.stdout);
                comm.lines()
                    .next()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .and_then(|line| std::path::Path::new(line).file_name())
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.to_ascii_lowercase().contains("fuigo"))
            }
            _ => false,
        }
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        is_fuigo_process(pid)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    /// The PROCESS-WIDE set is seeded once and the first writer wins, so every
    /// test here installs the SAME value. Tests that need a different set
    /// build their own [`TrustedApiOrigins`] instead (see
    /// `resolution_is_per_instance_and_needs_no_global`), which is exactly what
    /// the injectable value exists for. Coverage for the *uninitialised* case
    /// lives in `tests/trust_fails_closed.rs`, which needs its own process.
    const TEST_ORIGIN: &str = "https://api.fluxrouter.ai";
    fn init_test_origins() {
        set_trusted_api_origins([TEST_ORIGIN.to_string()]);
    }

    /// Two instances resolve independently, in one process, in any order.
    ///
    /// This is the shape the production mapping was untestable in: a single
    /// process-wide store means the first test to install a set decides the
    /// answer for every other test in the binary, so an assertion about a
    /// DIFFERENT set can only be made in a separate process. A value can be
    /// asserted here.
    #[test]
    fn resolution_is_per_instance_and_needs_no_global() {
        let first = TrustedApiOrigins::new(["https://first.example/v1".to_string()]);
        let second = TrustedApiOrigins::new(["https://second.example/v1".to_string()]);

        assert!(first.is_fuigo_api_bearer_url("https://first.example/v1"));
        assert!(!first.is_fuigo_api_bearer_url("https://second.example/v1"));
        assert!(second.is_fuigo_api_bearer_url("https://second.example/v1"));
        assert!(!second.is_fuigo_api_bearer_url("https://first.example/v1"));

        // Installing the process-wide fixture afterwards changes neither.
        init_test_origins();
        assert!(!first.is_fuigo_api_bearer_url(TEST_ORIGIN));
        assert!(!second.is_fuigo_api_bearer_url(TEST_ORIGIN));

        // Blank entries are dropped, so an unset endpoint cannot widen trust.
        let sparse = TrustedApiOrigins::new([
            "  ".to_string(),
            String::new(),
            " https://third.example/v1 ".to_string(),
        ]);
        assert_eq!(sparse.origins(), ["https://third.example/v1".to_string()]);
        assert!(TrustedApiOrigins::default().is_empty());
        assert!(!TrustedApiOrigins::default().is_fuigo_api_url("https://first.example/v1"));
    }

    /// The compiled proxy route is empty after severance, so nothing matches it.
    #[test]
    fn ipv6_loopback_is_a_cli_chat_proxy_url_like_its_ipv4_twin() {
        // Was dead: the old `host_str() == "::1"` arm never matched the bracketed `[::1]`.
        assert!(is_cli_chat_proxy_url("http://[::1]:8080/v1"));
        assert!(is_cli_chat_proxy_url("http://127.0.0.1:8080/v1"));
        assert!(is_cli_chat_proxy_url("http://localhost:8080/v1"));
    }

    #[test]
    fn canonical_loopback_host_is_exactly_the_three_names() {
        let yes = [
            "http://[::1]:1/",
            "ws://[::1]/",
            "http://127.0.0.1/",
            "http://LOCALHOST:9/",
        ];
        let no = [
            "http://127.0.0.2/",
            "http://[::2]/",
            "http://[::ffff:127.0.0.1]/",
            "http://localhost.example.com/",
            "http://example.com/",
            "file:///tmp/x",
        ];
        for u in yes {
            assert!(
                is_canonical_loopback_host(&reqwest::Url::parse(u).unwrap()),
                "{u}"
            );
        }
        for u in no {
            assert!(
                !is_canonical_loopback_host(&reqwest::Url::parse(u).unwrap()),
                "{u}"
            );
        }
    }

    #[test]
    fn test_is_cli_chat_proxy_url_has_no_compiled_route() {
        assert!(!is_cli_chat_proxy_url(
            "https://cli-chat-proxy.grok.com/v1/chat/completions"
        ));
    }
    #[test]
    fn test_is_cli_chat_proxy_url_rejects_public_api() {
        assert!(!is_cli_chat_proxy_url("https://api.x.ai/v1"));
    }
    #[test]
    fn test_is_cli_chat_proxy_url_rejects_spoofed_hostname() {
        assert!(!is_cli_chat_proxy_url(
            "https://cli-chat-proxy.grok.com.evil.example/v1"
        ));
    }
    #[test]
    fn test_is_cli_chat_proxy_url_rejects_v11_prefix_confusion() {
        assert!(!is_cli_chat_proxy_url(
            "https://cli-chat-proxy.grok.com/v11/chat/completions"
        ));
    }
    /// Refusal path: scheme-agnostic, matched on host, so a credential is
    /// refused even for a plaintext spelling of a configured origin.
    #[test]
    fn test_is_fuigo_api_url_follows_configuration() {
        init_test_origins();
        assert!(is_fuigo_api_url("https://api.fluxrouter.ai/v1"));
        assert!(is_fuigo_api_url(
            "https://api.fluxrouter.ai/v1/chat/completions"
        ));
        // Scheme-agnostic on purpose: refusal must fail closed.
        assert!(is_fuigo_api_url("http://api.fluxrouter.ai/v1"));

        // THE REGRESSION THIS FILE EXISTS FOR: no vendor is trusted by
        // compilation. x.ai is a configured API origin only if configured, and it is not.
        assert!(!is_fuigo_api_url("https://api.x.ai/v1"));
        assert!(!is_fuigo_api_url("https://x.ai"));

        assert!(!is_fuigo_api_url("https://api.openai.com/v1"));
        assert!(!is_fuigo_api_url("https://api.anthropic.com/v1"));
        assert!(!is_fuigo_api_url(
            "https://generativelanguage.googleapis.com"
        ));

        // A trailing root dot is the SAME host: DNS resolves `h.` and `h`
        // identically, and `is_fuigo_api_url` gates the enterprise
        // `disable_api_key_auth` kill switch. Treating them as different
        // origins would let a `base_url` evade a policy that is documented to
        // fail closed.
        assert!(is_fuigo_api_url("https://api.fluxrouter.ai./v1"));
        assert!(is_fuigo_api_url("https://API.FLUXROUTER.AI./v1"));

        // Suffix / prefix confusion against the CONFIGURED origin.
        assert!(!is_fuigo_api_url(
            "https://api.fluxrouter.ai.evil.example/v1"
        ));
        assert!(!is_fuigo_api_url(
            "https://evil-api.fluxrouter.ai.attacker.com/v1"
        ));
        assert!(!is_fuigo_api_url("https://prefixfluxrouter.ai/v1"));

        assert!(!is_fuigo_api_url("not-a-url"));
        assert!(!is_fuigo_api_url(""));
        // Loopback stays accepted here (mock servers); the bearer variant refuses it.
        assert!(is_fuigo_api_url("http://localhost:11434/v1"));
    }
    /// Attachment path: https only, no loopback, configured origins only.
    #[test]
    fn test_is_fuigo_api_bearer_url_follows_configuration() {
        init_test_origins();
        assert!(is_fuigo_api_bearer_url("https://api.fluxrouter.ai/v1"));
        // Host comparison is case-insensitive, as URL hosts are.
        assert!(is_fuigo_api_bearer_url("https://API.FLUXROUTER.AI/v1"));

        // Never over plaintext: a bearer must not cross an unencrypted hop.
        assert!(!is_fuigo_api_bearer_url("http://api.fluxrouter.ai/v1"));

        // Never to loopback: a co-located process could read the token.
        assert!(!is_fuigo_api_bearer_url("http://localhost:11434/v1"));
        assert!(!is_fuigo_api_bearer_url("https://localhost:11434/v1"));
        assert!(!is_fuigo_api_bearer_url("https://127.0.0.2:11434/v1"));
        assert!(!is_fuigo_api_bearer_url("https://[::1]:11434/v1"));

        // No vendor by default.
        assert!(!is_fuigo_api_bearer_url("https://api.x.ai/v1"));

        assert!(is_fuigo_api_bearer_url("https://api.fluxrouter.ai./v1"));

        // userinfo confusion: the real host is attacker.example.
        assert!(!is_fuigo_api_bearer_url(
            "https://api.fluxrouter.ai@attacker.example/v1"
        ));
        // Homograph: Cyrillic \u{0445} is not ASCII `x`. Kept from the original
        // suite because it guards the host comparison, not the vendor name.
        assert!(!is_fuigo_api_bearer_url("https://\u{0445}.ai/v1"));
        assert!(!is_fuigo_api_bearer_url("https://fluxr\u{043e}uter.ai/v1"));
    }

    /// `is_configured_api_origin` must NOT inherit `is_fuigo_api_url`'s
    /// unconditional loopback grant. It decides where `FUIGO_API_KEY` may be
    /// sent, and a models catalogue naming a local port would otherwise harvest
    /// it from any listener on the machine.
    #[test]
    fn configured_api_origin_does_not_grant_unconfigured_loopback() {
        init_test_origins();
        // The broad predicate grants loopback outright; the narrow one must not.
        assert!(is_fuigo_api_url("http://localhost:9999/v1"));
        assert!(!is_configured_api_origin("http://localhost:9999/v1"));
        assert!(!is_configured_api_origin("http://127.0.0.1:9999/v1"));
        assert!(!is_configured_api_origin("https://evil.example/v1"));

        // A configured host is allowed over https.
        assert!(is_configured_api_origin("https://api.fluxrouter.ai/v1"));
    }

    /// Configuring a host does not also opt it into cleartext.
    ///
    /// Choosing a remote endpoint is not choosing to put `FUIGO_API_KEY` on the
    /// wire in the clear, so the scheme is checked even for a host that is in
    /// the trust set.
    #[test]
    fn configured_api_origin_requires_https_for_remote_hosts() {
        init_test_origins();
        assert!(is_configured_api_origin("https://api.fluxrouter.ai/v1"));
        assert!(!is_configured_api_origin("http://api.fluxrouter.ai/v1"));
        // Nor via any other cleartext scheme.
        assert!(!is_configured_api_origin("ws://api.fluxrouter.ai/v1"));
        // The trailing-dot form of the same host is covered too.
        assert!(is_configured_api_origin("https://api.fluxrouter.ai./v1"));
        assert!(!is_configured_api_origin("http://api.fluxrouter.ai./v1"));
    }

    /// The loopback carve-out: a local gateway on `http://localhost:8080` is
    /// still reachable once configured.
    ///
    /// Asserted against the scheme rule alone because the trust set is
    /// process-wide, seeded first-write-wins and shared by every test in this
    /// process -- installing a loopback
    /// origin here would also make `http://localhost:9999` a configured host
    /// and silently defeat
    /// `configured_api_origin_does_not_grant_unconfigured_loopback`.
    #[test]
    fn configured_origin_scheme_rule_exempts_loopback_only() {
        assert!(configured_origin_scheme_allows("http://localhost:8080/v1"));
        assert!(configured_origin_scheme_allows("http://127.0.0.1:8080/v1"));
        assert!(configured_origin_scheme_allows("http://[::1]:8080/v1"));
        assert!(configured_origin_scheme_allows(
            "https://api.fluxrouter.ai/v1"
        ));

        assert!(!configured_origin_scheme_allows(
            "http://api.fluxrouter.ai/v1"
        ));
        // 127.0.0.2 is loopback per RFC 3330 and `Ipv4Addr::is_loopback`.
        assert!(configured_origin_scheme_allows("http://127.0.0.2:8080/v1"));
        // A hostname that merely contains "localhost" is not loopback.
        assert!(!configured_origin_scheme_allows(
            "http://localhost.evil.example/v1"
        ));
        assert!(!configured_origin_scheme_allows("not-a-url"));
    }
    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hello world", 5), "hello");
        assert_eq!(truncate("abc🎉🎉def", 5), "abc🎉🎉");
    }
    #[test]
    fn is_process_alive_current_process() {
        assert!(is_process_alive(std::process::id()));
    }
    #[test]
    fn is_process_alive_dead_pid() {
        assert!(!is_process_alive(4_000_000_000));
    }
    #[cfg(unix)]
    #[test]
    fn is_process_alive_init_process() {
        assert!(is_process_alive(1));
    }
    #[test]
    fn kill_process_by_pid_already_dead_is_ok() {
        assert!(kill_process_by_pid(4_000_000_000).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn kill_process_by_pid_terminates_live_child() {
        #[allow(clippy::disallowed_methods)]
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        kill_process_by_pid(pid).expect("kill should succeed");
        let status = child.wait().expect("wait child");
        assert!(
            !status.success(),
            "sleep was terminated, not exited cleanly"
        );
    }
    #[test]
    fn is_fuigo_process_self_true_impossible_pid_false() {
        assert!(is_fuigo_process(std::process::id()));
        assert!(!is_fuigo_process(u32::MAX));
    }
    #[test]
    fn is_fuigo_process_strict_self_true_impossible_pid_false() {
        assert!(is_fuigo_process_strict(std::process::id()));
        assert!(!is_fuigo_process_strict(u32::MAX));
    }
    #[cfg(unix)]
    #[test]
    fn kill_process_with_signal_sigkill_terminates_live_child() {
        #[allow(clippy::disallowed_methods)]
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        kill_process_with_signal(pid, KillSignal::Kill).expect("sigkill should succeed");
        let status = child.wait().expect("wait child");
        assert!(!status.success(), "sleep was killed, not exited cleanly");
    }

    // ---- Trust-set records (P17-R) ------------------------------------------
    //
    // These exercise `TrustSetChange::between` and `recorded_trust` on local
    // values, never the process-wide store, so they are schedule-independent.

    fn rt(origins: &[&str], hosts: &[&str]) -> RecordedTrust {
        RecordedTrust {
            origins: origins.iter().map(|s| s.to_string()).collect(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A configured endpoint can carry a credential; the record never does.
    #[test]
    fn a_trust_record_carries_only_scheme_host_and_port() {
        const SECRET_BEARING: &str =
            "https://alice:hunter2@GW.Corp.Example./v1/tenant-9f3a?api_key=sk-live-123";
        let set = TrustedApiOrigins::new([
            SECRET_BEARING.to_string(),
            "https://gw.corp.example:8443/v1".to_string(),
            "not a url sk-live-456".to_string(),
        ]);

        let change = TrustSetChange::between(None, &set);
        assert_eq!(
            change,
            TrustSetChange::Initial {
                // The userinfo entry admits nothing to the strict tier; its
                // host is admitted by the host-only tier.
                current: rt(&["https://gw.corp.example:8443"], &["gw.corp.example"]),
            }
        );
        let rendered = format!("{change:?}");
        for leaked in [
            "alice",
            "hunter2",
            "tenant-9f3a",
            "api_key",
            "sk-live",
            "/v1",
            "not a url",
        ] {
            assert!(
                !rendered.contains(leaked),
                "a trust record must not carry `{leaked}`: {rendered}"
            );
        }
    }

    /// The record is exactly what the matchers admit: for every probe URL, the
    /// strict predicates agree with `origins` and the host-only predicate agrees
    /// with `hosts` -- for a userinfo entry, an unparseable entry and a valid one.
    #[test]
    fn the_trust_record_agrees_with_the_matchers() {
        let set = TrustedApiOrigins::new([
            "https://u:p@userinfo.example/v1".to_string(),
            "::not a url::".to_string(),
            "https://valid.example:8443/v1".to_string(),
        ]);
        let recorded = set.recorded_trust();
        assert_eq!(
            recorded,
            rt(
                &["https://valid.example:8443"],
                &["userinfo.example", "valid.example"]
            )
        );
        for probe in [
            "https://userinfo.example/v1/chat",
            "https://valid.example:8443/v1/chat",
            "https://valid.example/v1/chat",
            "http://valid.example:8443/v1",
            "https://other.example/v1",
        ] {
            let url = reqwest::Url::parse(probe).unwrap();
            let origin = credential_origin(probe).unwrap();
            let host = normalized_host(&url).unwrap();
            assert_eq!(
                set.is_fuigo_api_bearer_url(probe),
                recorded.origins.contains(&origin),
                "strict tier disagrees with the record for {probe}"
            );
            assert_eq!(
                set.is_configured_api_origin(probe),
                recorded.origins.contains(&origin),
                "configured-origin tier disagrees with the record for {probe}"
            );
            assert_eq!(
                set.is_fuigo_api_url(probe),
                recorded.hosts.contains(&host),
                "host-only tier disagrees with the record for {probe}"
            );
        }
    }

    /// Removing userinfo from an endpoint makes a host credential-trusted that
    /// was not: a widening, and it must be recorded as one (Astra, P17-R v2 #1).
    /// The reverse edit is a narrowing.
    #[test]
    fn dropping_userinfo_from_an_endpoint_is_a_recorded_widening() {
        let with_userinfo = TrustedApiOrigins::new(["https://user:pass@gw.example/v1".to_string()]);
        let plain = TrustedApiOrigins::new(["https://gw.example/v1".to_string()]);
        assert!(!with_userinfo.is_fuigo_api_bearer_url("https://gw.example/v1/chat"));
        assert!(plain.is_fuigo_api_bearer_url("https://gw.example/v1/chat"));

        let widened = TrustSetChange::between(Some(&with_userinfo), &plain);
        assert_eq!(
            widened,
            TrustSetChange::Changed {
                previous: rt(&[], &["gw.example"]),
                current: rt(&["https://gw.example"], &["gw.example"]),
                added: rt(&["https://gw.example"], &[]),
                removed: rt(&[], &[]),
            }
        );
        assert!(widened.is_widening());

        let narrowed = TrustSetChange::between(Some(&plain), &with_userinfo);
        assert!(matches!(narrowed, TrustSetChange::Changed { .. }));
        assert!(!narrowed.is_widening());
    }

    /// Editing only the path of an endpoint admits exactly the same URLs, so it
    /// must not be reported as a new trusted origin.
    #[test]
    fn a_path_only_edit_is_not_a_trust_change() {
        let before = TrustedApiOrigins::new(["https://gw.corp.example/v1".to_string()]);
        let after = TrustedApiOrigins::new(["https://gw.corp.example:443/v2/chat?x=1".to_string()]);
        let change = TrustSetChange::between(Some(&before), &after);
        assert_eq!(
            change,
            TrustSetChange::Unchanged {
                current: rt(&["https://gw.corp.example"], &["gw.corp.example"]),
            }
        );
        assert!(!change.is_widening());
    }

    /// A moved endpoint is recorded as a widening that names the new origin and
    /// the one it replaced, in both tiers.
    #[test]
    fn a_moved_endpoint_is_recorded_as_a_widening_naming_both_origins() {
        let before = TrustedApiOrigins::new(["https://old.gateway.example/v1".to_string()]);
        let after =
            TrustedApiOrigins::new(["https://new.gateway.example/v1?token=t0k3n".to_string()]);
        let change = TrustSetChange::between(Some(&before), &after);
        assert_eq!(
            change,
            TrustSetChange::Changed {
                previous: rt(&["https://old.gateway.example"], &["old.gateway.example"]),
                current: rt(&["https://new.gateway.example"], &["new.gateway.example"]),
                added: rt(&["https://new.gateway.example"], &["new.gateway.example"]),
                removed: rt(&["https://old.gateway.example"], &["old.gateway.example"]),
            }
        );
        assert!(change.is_widening());

        let narrowed = TrustSetChange::between(Some(&after), &TrustedApiOrigins::default());
        assert!(matches!(narrowed, TrustSetChange::Changed { .. }));
        assert!(!narrowed.is_widening());
    }

    /// P30, the policy pin. The two destination trust classes answer independently, and the case
    /// the packet was filed for is decided deliberately: a user's own HTTPS gateway that they
    /// configured receives the session bearer (credential delivery follows configuration) and is
    /// NOT granted identity disclosure (identity follows the compiled FluxRouter-operated check,
    /// which no configuration can widen). `api.openai.com` configured as an origin is the leak P15
    /// closed, and stays closed. FluxRouter itself, configured, gets both.
    ///
    /// Resolved against a local instance, so it neither reads nor writes the process-wide set.
    #[test]
    fn credential_delivery_and_identity_disclosure_are_decided_independently() {
        use fuigo_extra_ca::fluxrouter::IdentityDisclosure;
        let configured = TrustedApiOrigins::new([
            "https://my.gateway.example/v1".to_string(),
            "https://api.openai.com/v1".to_string(),
            "https://api.fluxrouter.ai/v1".to_string(),
        ]);
        for (url, identity) in [
            ("https://my.gateway.example/v1/chat/completions", false),
            ("https://api.openai.com/v1/responses", false),
            ("https://api.fluxrouter.ai/v1/chat/completions", true),
        ] {
            assert!(
                configured.is_fuigo_api_bearer_url(url),
                "{url} is configured, so the session bearer may be delivered to it"
            );
            assert!(
                configured.is_configured_api_origin(url),
                "{url} is configured, so FUIGO_API_KEY may be delivered to it"
            );
            assert_eq!(
                IdentityDisclosure::for_destination(url).is_permitted(),
                identity,
                "{url}: identity disclosure must not follow configuration"
            );
        }
        // And the converse: FluxRouter-operated does not imply a credential. An installation that
        // did not configure FluxRouter must not send its credential there just because the host is
        // the compiled one.
        let elsewhere = TrustedApiOrigins::new(["https://my.gateway.example/v1".to_string()]);
        let fluxrouter = "https://api.fluxrouter.ai/v1/chat/completions";
        assert!(IdentityDisclosure::for_destination(fluxrouter).is_permitted());
        assert!(
            !elsewhere.is_fuigo_api_bearer_url(fluxrouter),
            "the compiled FluxRouter host must not be granted the credential unless configured"
        );
        assert!(!elsewhere.is_configured_api_origin(fluxrouter));
    }
}
