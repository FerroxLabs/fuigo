//! Port of the Flux refusal classification reference.
//! Reference action precedence plus request-host scoping at the engine boundary.
use crate::error::{UpstreamError, is_upstream_slug};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::sync::LazyLock;
use serde::{Serialize, Deserialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Stop,
    Pause,
    Backoff,
    RetryOnce,
    Pass,
}
impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stop => "STOP",
            Self::Pause => "PAUSE",
            Self::Backoff => "BACKOFF",
            Self::RetryOnce => "RETRY_ONCE",
            Self::Pass => "PASS",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub reason: String,
    pub action: Action,
    pub wait: String,
}
impl Classification {
    pub fn is_terminal(&self) -> bool {
        matches!(self.action, Action::Stop | Action::Pause)
    }
    pub fn refresh_eligible(&self, status: u16, refreshable: bool) -> bool {
        refreshable
            && status == 401
            && self.reason == "keyRefused"
            && self.action == Action::Stop
            && self.wait == "-"
    }
}
pub const FINAL_ORDER: &[(&str, &str)] = &[
    ("key_revoked", "keyRevoked"),
    ("key_not_found", "keyNotFound"),
    ("entitlement_missing", "keyAccess"),
    ("subscription_account_mismatch", "keyAccess"),
    ("authorization_state_unknown", "accessUnknown"),
    ("account_monthly_budget_exhausted", "accountCeiling"),
    ("key_budget_reached", "keyBudget"),
    ("key_lifetime_cap_exhausted", "keyLifetime"),
    ("free_cap_reached", "freeCap"),
    ("free_tier_exhausted", "freeCredit"),
    ("builder_auto_bump_eligible", "requestCap"),
    ("cap_reached", "planCap"),
    ("credit_exhausted", "credit"),
    ("credit_hold", "creditHold"),
    ("credit_unresolved", "unresolved"),
    ("monthly_cap", "spendCap"),
    ("daily_cap", "spendCap"),
    ("hourly_burn_limit", "hourly"),
];
pub const TRANSIENT: &[&str] = &[
    "batch_concurrency",
    "batch_rate",
    "billing_system_degraded",
    "key_rate_limit",
    "model_cooling_down",
    "provider_rate_limited",
    "tier_rpm_limit",
];
const OVERRIDE_TEXT: &[(&[&str], &str)] = &[
    (
        &["Free tier monthly allowance exhausted. Upgrade to Builder"],
        "fluxStop",
    ),
    (&["plan allowance", "paused until"], "planAllowance"),
    (&["overage cap"], "spendCap"),
    (&["$1 free credit is used up"], "freeCredit"),
];
const TEXT_RULES: &[(&[&str], &str)] = &[
    (&["monthly free-tier token allowance"], "freeCap"),
    (&["10M request cap reached"], "requestCap"),
    (&["Monthly cap reached"], "planCap"),
    (&["API key has been revoked"], "keyRevoked"),
    (&["no active Flux entitlement"], "keyAccess"),
    (&["does not resolve to this account"], "keyAccess"),
    (&["No Flux key record"], "keyNotFound"),
    (
        &["entitlement state could not be interpreted"],
        "accessUnknown",
    ),
    (&["bot has reached its"], "botBudget"),
    (&["token monthly limit"], "keyTokens"),
    (&["monthly budget"], "keyBudget"),
    (&["lifetime spend cap"], "keyLifetime"),
    (&["monthly spend ceiling"], "accountCeiling"),
    (&["credit balance is exhausted"], "credit"),
    (&["Cloud credit is exhausted"], "credit"),
    (&["credit is on hold"], "creditHold"),
    (&["could not be verified"], "unresolved"),
    (&["spend cap is reached"], "spendCap"),
];
const RATE_TEXT: &[&str] = &[
    "RateLimitError",
    "Rate limit",
    "No deployments available",
    "Limit resets at",
    "retry shortly",
];

pub fn slug(v: &Value) -> Option<String> {
    v.as_str()
        .filter(|s| is_upstream_slug(s))
        .map(str::to_owned)
}
pub fn header_wait(v: &str) -> Option<u64> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse::<u64>().ok().filter(|v| *v <= 7200)
}
pub fn wire_wait(v: &Value) -> Option<u64> {
    v.as_u64().filter(|v| *v <= 7200)
}
fn first_text(text: &str, rules: &[(&[&str], &'static str)]) -> Option<&'static str> {
    rules
        .iter()
        .find(|(needles, _)| needles.iter().all(|n| text.contains(n)))
        .map(|(_, r)| *r)
}
fn text_wait(text: &str, now: DateTime<Utc>) -> Option<u64> {
    static WAITS: LazyLock<[Regex; 3]> = LazyLock::new(|| [
        r"Retry in (\d+)s",
        r"Retry after (\d+) seconds?",
        r"[Tt]ry again in (\d+) ?s(?:econds)?",
    ].map(|pattern| Regex::new(pattern).unwrap()));
    static RESET_TIME: LazyLock<Regex> = LazyLock::new(|| Regex::new(
        r"Limit resets at: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC"
    ).unwrap());
    for pattern in WAITS.iter() {
        if let Some(m) = pattern.captures(text) {
            return Some(m[1].parse::<u64>().unwrap_or(u64::MAX));
        }
    }
    let re = &*RESET_TIME;
    let m = re.captures(text)?;
    let t = chrono::NaiveDateTime::parse_from_str(&m[1], "%Y-%m-%d %H:%M:%S")
        .ok()?
        .and_utc();
    let seconds = (t - now).num_seconds();
    (seconds > 0).then_some(seconds as u64)
}
#[derive(Debug)]
pub struct Signals {
    pub endpoint: String,
    pub status: u16,
    pub codes: Vec<String>,
    pub limit: Option<String>,
    pub text: String,
    pub wait: Option<u64>,
    pub hold_header: bool,
}
fn vocab(c: &str) -> bool {
    FINAL_ORDER.iter().any(|(k, _)| *k == c) || TRANSIENT.contains(&c) || c == "concurrency"
}
fn codes(values: impl IntoIterator<Item = Option<String>>) -> Vec<String> {
    let mut out = Vec::new();
    for c in values.into_iter().flatten() {
        if vocab(&c) && !out.contains(&c) {
            out.push(c);
        }
    }
    out
}
fn header<'a>(headers: &'a Value, name: &str) -> Option<&'a Value> {
    headers
        .as_object()?
        .iter()
        .rev()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}
pub fn extract(
    endpoint: &str,
    status: u16,
    headers: &Value,
    body: &Value,
    now: DateTime<Utc>,
) -> Signals {
    let e = &body["error"];
    let p = &e["provider_specific_fields"];
    let pe = &p["error"];
    let text = [&e["message"], &p["message"], &pe["message"]]
        .into_iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    let wait = header(headers, "retry-after")
        .and_then(Value::as_str)
        .and_then(header_wait)
        .or_else(|| {
            [&e["retry_after"], &p["retry_after"], &pe["retry_after"]]
                .into_iter()
                .find_map(wire_wait)
        })
        .or_else(|| text_wait(&text, now))
        .map(|w| w.clamp(1, 7200));
    Signals {
        endpoint: endpoint.into(),
        status,
        codes: codes([
            header(headers, "x-flux-hold-reason").and_then(slug),
            slug(&e["state"]),
            slug(&e["error"]),
            slug(&e["code"]),
            slug(&e["type"]),
            slug(pe),
            slug(&pe["state"]),
            slug(&pe["type"]),
            slug(&pe["error"]),
        ]),
        limit: slug(&e["limit"])
            .or_else(|| slug(&p["limit"]))
            .or_else(|| slug(&pe["limit"])),
        text,
        wait,
        hold_header: header(headers, "x-flux-hold-reason").is_some(),
    }
}
pub fn from_upstream(u: &UpstreamError, text: &str, now: DateTime<Utc>) -> Signals {
    Signals {
        endpoint: "resp".into(),
        status: u.http_status.unwrap_or(0),
        codes: codes(
            [u.hold_reason.clone()]
                .into_iter()
                .chain(u.codes.iter().cloned().map(Some))
                .chain([u.state.clone(), u.code.clone(), u.error_type.clone()]),
        ),
        limit: u.limit.clone(),
        text: text.into(),
        wait: u
            .retry_after_s
            .or_else(|| text_wait(text, now))
            .map(|w| w.clamp(1, 7200)),
        hold_header: u.hold_reason.is_some(),
    }
}
fn subtype(s: &Signals) -> &'static str {
    match s.limit.as_deref() {
        Some("monthly_spend") => return "keyBudget",
        Some("monthly_tokens") => return "keyTokens",
        Some("bot_monthly_spend") => return "botBudget",
        _ => (),
    }
    match first_text(&s.text, TEXT_RULES) {
        Some(r @ ("botBudget" | "keyTokens" | "keyBudget")) => r,
        _ => "keyBudget",
    }
}
fn stop_reason(s: &Signals) -> &'static str {
    if s.endpoint == "chat" && s.codes.iter().any(|c| c == "free_tier_exhausted") && !s.hold_header
    {
        return "fluxStop";
    }
    if let Some(r) = first_text(&s.text, OVERRIDE_TEXT) {
        return r;
    }
    for (c, r) in FINAL_ORDER {
        if s.codes.iter().any(|v| v == c) {
            return if *c == "key_budget_reached" {
                subtype(s)
            } else {
                r
            };
        }
    }
    first_text(&s.text, TEXT_RULES).unwrap_or(if matches!(s.status, 401 | 403) {
        "keyRefused"
    } else {
        "fluxStop"
    })
}
pub fn decide(s: &Signals) -> Classification {
    let terminal_text = first_text(&s.text, OVERRIDE_TEXT)
        .or_else(|| first_text(&s.text, TEXT_RULES))
        .is_some();
    let held =
        s.codes.iter().any(|c| c == "concurrency") || s.text.contains("temporarily reserved");
    let transient = s.codes.iter().any(|c| TRANSIENT.contains(&c.as_str()))
        || RATE_TEXT.iter().any(|t| s.text.contains(t));
    // ACTION_STEPS: terminal status, final code, terminal text, hold, transient,
    // known-wait 429, unknown 429, 5xx. First match wins.
    let action = if matches!(s.status, 401 | 402 | 403) {
        Action::Stop
    } else if s
        .codes
        .iter()
        .any(|c| FINAL_ORDER.iter().any(|(k, _)| c == k))
    {
        Action::Stop
    } else if terminal_text {
        Action::Stop
    } else if held {
        Action::RetryOnce
    } else if transient {
        Action::Backoff
    } else if s.status == 429 && s.wait.is_some() {
        Action::Backoff
    } else if s.status == 429 {
        Action::Pause
    } else if s.status >= 500 {
        Action::RetryOnce
    } else {
        Action::Pass
    };
    let (reason, wait) = match action {
        Action::Stop => {
            let r = stop_reason(s);
            (
                r,
                if r == "hourly" {
                    s.wait.map(|w| format!("reset+{w}")).unwrap_or("-".into())
                } else {
                    "-".into()
                },
            )
        }
        Action::Pause => ("unknownLimit", "-".into()),
        Action::RetryOnce => (
            if held { "hold" } else { "busy" },
            s.wait.unwrap_or(2).to_string(),
        ),
        Action::Backoff => (
            "busy",
            s.wait.map(|w| w.to_string()).unwrap_or("ladder".into()),
        ),
        Action::Pass => ("other", "-".into()),
    };
    Classification {
        reason: reason.into(),
        action,
        wait,
    }
}
/// Route identity comes from the actual request URL, independently of response signals.
pub fn is_flux_routed(request_url: &reqwest::Url, configured_flux_base: Option<&str>) -> bool {
    let Some(host) = request_url.host_str().map(|h| h.trim_end_matches('.')) else {
        return false;
    };
    host == "fluxrouter.ai"
        || host.ends_with(".fluxrouter.ai")
        || configured_flux_base
            .and_then(|base| reqwest::Url::parse(base).ok())
            .and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_owned()))
            .is_some_and(|configured| configured == host)
}

/// Off-Flux requests retain the parent's retry and recovery policy in full.
pub fn decide_for_request(s: &Signals, flux_routed: bool) -> Classification {
    if !flux_routed { return Classification::pass(); }
    decide(s)
}

impl Classification {
    pub fn pass() -> Self {
        Self { reason: "other".into(), action: Action::Pass, wait: "-".into() }
    }
}


pub fn classify(
    endpoint: &str,
    status: u16,
    headers: &Value,
    body: &Value,
    now: DateTime<Utc>,
) -> Classification {
    decide(&extract(endpoint, status, headers, body, now))
}

fn json_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|n| n != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// The frozen wire extraction. No text is stored in this object.
pub fn fuigo_upstream(status: u16, headers: &Value, body: &Value) -> UpstreamError {
    let e = &body["error"];
    let p = &e["provider_specific_fields"];
    let pe = &p["error"];
    let code = slug(&e["error"])
        .or_else(|| slug(pe))
        .or_else(|| slug(&pe["state"]))
        .or_else(|| slug(&pe["type"]))
        .or_else(|| slug(&e["code"]).filter(|s| !s.chars().all(char::is_numeric)));
    let resets = if json_truthy(&e["resets_at"]) {
        &e["resets_at"]
    } else {
        &p["resets_at"]
    };
    let mut all_codes = Vec::new();
    for code in [
        slug(&e["state"]),
        slug(&e["error"]),
        slug(&e["code"]).filter(|c| !c.bytes().all(|b| b.is_ascii_digit())),
        slug(&e["type"]),
        slug(pe),
        slug(&pe["state"]),
        slug(&pe["type"]),
        slug(&pe["error"]),
    ]
    .into_iter()
    .flatten()
    {
        if !all_codes.contains(&code) {
            all_codes.push(code);
        }
    }
    UpstreamError {
        flux_routed: true,
        classification: None,
        codes: all_codes,
        http_status: Some(status),
        error_type: slug(&e["type"]).or_else(|| {
            e["type"]
                .as_str()
                .filter(|s| crate::upstream_vocab::LITELLM_EXCEPTIONS.contains(s))
                .map(str::to_owned)
        }),
        state: slug(&e["state"]),
        code,
        hold_reason: header(headers, "x-flux-hold-reason").and_then(slug),
        limit: slug(&e["limit"])
            .or_else(|| slug(&p["limit"]))
            .or_else(|| slug(&pe["limit"])),
        retry_after_s: header(headers, "retry-after")
            .and_then(Value::as_str)
            .and_then(header_wait)
            .or_else(|| {
                [&e["retry_after"], &p["retry_after"], &pe["retry_after"]]
                    .into_iter()
                    .find_map(wire_wait)
            }),
        resets_at: resets
            .as_str()
            .filter(|s| {
                RESET_DATE.is_match(s)
            })
            .map(str::to_owned),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptState {
    Open,
    AuthRefresh,
    Refreshed,
    Terminal,
    Done,
}
impl PromptState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::AuthRefresh => "AUTH_REFRESH",
            Self::Refreshed => "REFRESHED",
            Self::Terminal => "TERMINAL",
            Self::Done => "DONE",
        }
    }
}
/// Per-prompt dispatch monitor. Request bodies deliberately do not key the invariant.
#[derive(Debug)]
pub struct PromptSM {
    pub refreshable: bool,
    pub state: PromptState,
    pub dispatches: usize,
    pub after_terminal: usize,
    pub main: usize,
    pub side: usize,
    pub refreshes: usize,
    pub resubmits: usize,
    pub violations: Vec<String>,
}
impl PromptSM {
    pub fn new(refreshable: bool) -> Self {
        Self {
            refreshable,
            state: PromptState::Open,
            dispatches: 0,
            after_terminal: 0,
            main: 0,
            side: 0,
            refreshes: 0,
            resubmits: 0,
            violations: vec![],
        }
    }
    pub fn dispatch(&mut self, kind: &str) {
        assert!(
            [
                "main",
                "side",
                "sampler_retry",
                "refresh_resubmit",
                "provider_4c",
                "transient_4d",
                "compact",
                "resume"
            ]
            .contains(&kind)
        );
        self.dispatches += 1;
        if self.state == PromptState::Terminal {
            self.after_terminal += 1;
            self.violations
                .push(format!("{kind} dispatched after terminal"));
            return;
        }
        match kind {
            "main" => {
                self.main += 1;
                if self.main > 1 {
                    self.violations.push("second main dispatch".into());
                }
            }
            "side" => {
                self.side += 1;
                if self.side > 1 {
                    self.violations.push("second side dispatch".into());
                }
            }
            "refresh_resubmit" => {
                if self.state != PromptState::Refreshed {
                    self.violations
                        .push("resubmit without an eligible refresh".into());
                }
                self.resubmits += 1;
                if self.resubmits > 1 {
                    self.violations.push("second resubmit".into());
                }
            }
            _ => {
                if matches!(
                    self.state,
                    PromptState::AuthRefresh | PromptState::Refreshed
                ) {
                    self.violations
                        .push(format!("{kind} during the auth refresh exception"));
                }
            }
        }
    }
    pub fn refresh_token(&mut self) {
        if self.state != PromptState::AuthRefresh {
            self.violations
                .push(format!("token refresh in state {}", self.state.as_str()));
            return;
        }
        self.refreshes += 1;
        self.state = PromptState::Refreshed;
    }
    pub fn respond(&mut self, kind: &str, status: u16, result: Option<&Classification>) {
        if kind == "side" {
            return;
        }
        let Some(result) = result else {
            self.state = PromptState::Done;
            return;
        };
        if kind == "refresh_resubmit" {
            self.state = PromptState::Terminal;
            return;
        }
        if result.is_terminal() {
            self.state = if self.state == PromptState::Open
                && self.refreshes < 1
                && result.refresh_eligible(status, self.refreshable)
            {
                PromptState::AuthRefresh
            } else {
                PromptState::Terminal
            };
        }
    }
    pub fn verdict(&self) -> (&str, usize, &str) {
        (
            if self.violations.is_empty() {
                "ok"
            } else {
                "violation"
            },
            self.dispatches,
            self.state.as_str(),
        )
    }
}

pub fn key_rejected_mark(reason: &str) -> bool {
    reason == "keyRevoked"
}

pub(crate) static RESET_DATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$").unwrap());
