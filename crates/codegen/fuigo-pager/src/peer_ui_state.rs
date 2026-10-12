//! Peer messaging in the TUI, packet 12b: the live state behind packet 12's rows and dialog, fed by the shell's six peer events
//! and its `_fuigo/peer/*` methods (packet 13). Everything is behind `features.peer_messaging` ([`peer_ui_enabled`]): with it off
//! no event is read, no request is built, no row or dialog exists.
//!
//! Trust: every string in an event or a reply is DATA. It is parsed into typed fields (a `heldId` must be `h-<32 hex>`, a token is
//! an opaque string that is never printed or logged), shown only through packet 12's escaping builders, and never executed,
//! expanded (`@file`, `/`, `!`) or put in the prompt input. Unknown events and malformed payloads are ignored.
//! A token lives only inside the open dialog and is consumed by the one decision made with it; it is never retried.

use std::collections::VecDeque;

use serde_json::{Value, json};

use crate::peer_ui::{
    PeerDialogOutcome, PeerHold, PeerHoldDialog, PeerNotice, held_row_text, notice_row_text, now_secs, peer_ui_enabled, text_field,
};

pub const METHOD_CONFIGURE: &str = "fuigo/peer/configure";
pub const METHOD_LIST_HELD: &str = "fuigo/peer/list_held";
pub const METHOD_RELEASE: &str = "fuigo/peer/release";
/// JSON-RPC code of every peer failure (`data.reason` says which).
pub const PEER_ERROR_CODE: i32 = -32011;
/// The key that opens the hold dialog (only acts while something is held).
pub const OPEN_KEY_HINT: &str = "Alt+h";

const MAX_HOLDS: usize = 32;
const RECENT_CAP: usize = 16;
const MAX_REASONS: usize = 8;
const MAX_REASON_CHARS: usize = 32;
const MAX_NAME_CHARS: usize = 64;
const MAX_MODE_CHARS: usize = 32;
const MAX_DETAIL_CHARS: usize = 200;
/// A `peer_warning` text is capped when parsed, not only when drawn.
const MAX_WARNING_CHARS: usize = 200;
/// Peer notice rows allowed per window; past it ONE "suppressed" row until the window ends.
const NOTICE_LIMIT: u32 = 20;
const NOTICE_WINDOW_SECS: u64 = 60;
const SUPPRESSED_NOTICE: &str = "more peer notices suppressed";
const MAX_TOKEN: usize = 512;
const REASON_COLS: usize = 32;

/// `h-` + 32 hex: the only id shape the pager accepts from the shell (it goes back in `release`).
pub fn is_held_id(s: &str) -> bool {
    s.len() == 34 && s.starts_with("h-") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// A single-use release token. Its `Debug` hides the value, so no log line or panic message can carry it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    Held(PeerHold),
    Released(Option<String>),
    Refused(Option<String>),
    Expired(Option<String>),
    Reheld(Option<String>),
    Warning { text: String, subject: String },
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn held_id_of(v: &Value) -> Option<String> {
    str_of(v, "heldId").filter(|s| is_held_id(s)).map(str::to_owned)
}

fn cap_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn hold_from(v: &Value) -> Option<PeerHold> {
    let from = v.get("from")?;
    let reasons: Vec<String> = v
        .get("reasons")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .take(MAX_REASONS)
        .map(|r| cap_chars(r, MAX_REASON_CHARS))
        .collect();
    let field = |key: &str, n: usize| cap_chars(str_of(from, key).unwrap_or_default(), n);
    Some(PeerHold {
        message_id: held_id_of(v)?,
        from_name: field("name", MAX_NAME_CHARS),
        from_ref: field("ref", MAX_NAME_CHARS),
        sender_mode: field("mode", MAX_MODE_CHARS),
        own_mode: String::new(),
        reasons,
        denial_counts: Vec::new(),
        expires_at_secs: v.get("expiresAt").and_then(Value::as_u64)?,
        first_line: String::new(),
        detail: str_of(v, "detail").map(|d| cap_chars(d, MAX_DETAIL_CHARS)),
    })
}

/// The `update` object of a `fuigo/session_notification` as a peer event. `None` for anything else or anything malformed.
pub fn parse_event(update: &Value) -> Option<PeerEvent> {
    let id = || held_id_of(update);
    Some(match str_of(update, "sessionUpdate")? {
        "peer_held" => PeerEvent::Held(hold_from(update)?),
        "peer_released" => PeerEvent::Released(id()),
        "peer_refused" => PeerEvent::Refused(id()),
        "peer_expired" => PeerEvent::Expired(id()),
        "peer_reheld" => PeerEvent::Reheld(id()),
        "peer_warning" => PeerEvent::Warning {
            text: cap_chars(str_of(update, "text").unwrap_or("a peer messaging notice"), MAX_WARNING_CHARS),
            subject: cap_chars(str_of(update, "subject").unwrap_or_default(), MAX_NAME_CHARS),
        },
        _ => return None,
    })
}

/// Is this raw `fuigo/session_notification` payload a peer event (by name only)? Cheap pre-check before the typed parse.
pub fn peer_update_session_id(params: &Value) -> Option<String> {
    let name = str_of(params.get("update")?, "sessionUpdate")?;
    if !name.starts_with("peer_") {
        return None;
    }
    str_of(params, "sessionId").map(str::to_owned)
}

// ---------------------------------------------------------------------------------------------------------------------
// Requests and replies
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCall {
    /// Tell the shell a real terminal user is attached.
    Configure,
    /// Fetch the held rows and fresh tokens. `reopen`: open the dialog on the first row when it arrives.
    ListHeld { reopen: bool },
    Decide { held_id: String, token: Token, refuse: bool },
}

impl PeerCall {
    pub fn method(&self) -> &'static str {
        match self {
            Self::Configure => METHOD_CONFIGURE,
            Self::ListHeld { .. } => METHOD_LIST_HELD,
            Self::Decide { .. } => METHOD_RELEASE,
        }
    }

    pub fn params(&self, session_id: &str) -> Value {
        match self {
            // Attended, default policy: the same admission the pager's in-process agent starts with.
            Self::Configure => json!({ "sessionId": session_id, "optIn": true, "operator": "attended" }),
            Self::ListHeld { .. } => json!({ "sessionId": session_id }),
            Self::Decide { held_id, token, refuse } => json!({
                "sessionId": session_id,
                "heldId": held_id,
                "token": token.0,
                "action": if *refuse { "refuse" } else { "release" },
            }),
        }
    }
}

/// A typed peer failure (`-32011`, `data.reason`), or any other transport failure with an empty reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRpcError {
    pub reason: String,
}

fn reason_in(v: &Value, depth: u8) -> Option<String> {
    if let Some(r) = v.get("reason").and_then(Value::as_str) {
        return Some(r.to_owned());
    }
    if depth == 0 {
        return None;
    }
    v.as_object()?.values().find_map(|c| reason_in(c, depth - 1))
}

impl PeerRpcError {
    pub fn from_acp(e: &agent_client_protocol::Error) -> Self {
        let code: i32 = e.code.into();
        let typed = code == PEER_ERROR_CODE;
        let reason = typed.then(|| e.data.as_ref().and_then(|d| reason_in(d, 3))).flatten().unwrap_or_default();
        Self { reason }
    }

    /// Stale: the token or the row is gone; the list is refreshed once and the user chooses again.
    pub fn is_stale(&self) -> bool {
        matches!(self.reason.as_str(), "bad_token" | "not_found")
    }

    /// One plain line. The reason is matched against a fixed set; an unknown one is shown capped and escaped.
    pub fn plain_line(&self) -> String {
        match self.reason.as_str() {
            "unavailable" => "Peer messaging is unavailable for this session right now.".to_owned(),
            "no_operator" => "This session has no operator who can release or refuse held peer messages.".to_owned(),
            "not_opted_in" => "This session is not opted in to peer messaging.".to_owned(),
            "expired" => "That held peer message has expired.".to_owned(),
            "bad_token" | "not_found" => "That held peer message changed. The list was refreshed; choose again.".to_owned(),
            "" => "Peer messaging request failed.".to_owned(),
            other => format!("Peer messaging request failed: {}", text_field(other, REASON_COLS)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRpcOutcome {
    Configured(Result<(), PeerRpcError>),
    Held { reopen: bool, result: Result<Vec<(PeerHold, Token)>, PeerRpcError> },
    /// `Ok` carries the shell's result word (`delivered`, `reheld`, `dropped`, `expired`, `refused`).
    Decided { held_id: String, refuse: bool, result: Result<String, PeerRpcError> },
}

fn parse_held_rows(reply: &Value) -> Vec<(PeerHold, Token)> {
    let Some(rows) = reply.get("held").and_then(Value::as_array) else { return Vec::new() };
    rows.iter()
        .filter_map(|r| {
            let token = str_of(r, "token").filter(|t| !t.is_empty() && t.len() <= MAX_TOKEN)?;
            Some((hold_from(r)?, Token(token.to_owned())))
        })
        .take(MAX_HOLDS)
        .collect()
}

/// Send one call and parse the reply. Never retries.
pub async fn perform(tx: &fuigo_acp_lib::AcpAgentTx, session_id: &str, call: PeerCall) -> PeerRpcOutcome {
    let params = call.params(session_id);
    let raw = serde_json::value::to_raw_value(&params).expect("serialize peer params");
    let req = agent_client_protocol::ExtRequest::new(call.method(), raw.into());
    let reply = fuigo_acp_lib::acp_send(req, tx).await.map(|resp| {
        let v: Value = serde_json::from_str(resp.0.get()).unwrap_or_default();
        v.get("result").cloned().unwrap_or(v)
    });
    let reply = reply.map_err(|e| PeerRpcError::from_acp(&e));
    match call {
        PeerCall::Configure => PeerRpcOutcome::Configured(reply.map(|_| ())),
        PeerCall::ListHeld { reopen } => PeerRpcOutcome::Held { reopen, result: reply.map(|v| parse_held_rows(&v)) },
        PeerCall::Decide { held_id, refuse, .. } => PeerRpcOutcome::Decided {
            held_id,
            refuse,
            result: reply.map(|v| str_of(&v, "result").unwrap_or("unknown").to_owned()),
        },
    }
}

/// The opt-in sent once per session, only while a real terminal user is there. `None` with the flag off or without a terminal.
pub fn startup_call() -> Option<PeerCall> {
    use std::io::IsTerminal;
    (peer_ui_enabled() && std::io::stdin().is_terminal() && std::io::stdout().is_terminal()).then_some(PeerCall::Configure)
}

// ---------------------------------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct OpenDialog {
    dialog: PeerHoldDialog,
    token: Token,
}

/// What one agent view knows about peer holds.
#[derive(Debug, Default)]
pub struct PeerUiState {
    holds: Vec<PeerHold>,
    /// Holds that just went (released, refused, expired): keeps the name for the notice and the row for a `peer_reheld`.
    recent: VecDeque<PeerHold>,
    dialog: Option<OpenDialog>,
    /// Notice rate limit: start of the current window, rows shown in it, whether the "suppressed" row was shown.
    notice_window: (u64, u32, bool),
    /// The session id this view already sent `configure` for.
    configured_sid: Option<String>,
    /// The shell exposes no influence state to the client (grep `peer_influenced`: hooks only), so this is never set. The marker
    /// text builder stays unconnected.
    pub influenced: bool,
    /// Set when the dialog's own key handler took a key (see `AppView::handle_input_at_with_paste_provenance`); cleared before each event.
    key_taken: bool,
}

impl PeerUiState {
    /// Forget whether the dialog took the last key (called before every event is dispatched).
    pub fn clear_key_taken(&mut self) {
        self.key_taken = false;
    }

    /// Record that the dialog's own key handler took this key.
    pub fn note_key_taken(&mut self) {
        self.key_taken = true;
    }

    /// Whether the dialog's own key handler took the key just dispatched.
    pub fn key_taken(&self) -> bool {
        self.key_taken
    }

    pub fn held_count(&self) -> usize {
        self.holds.len()
    }

    /// The held row (and, over it, the dialog) are drawn only with the flag on and something held.
    pub fn row_visible(&self) -> bool {
        peer_ui_enabled() && !self.holds.is_empty()
    }

    /// The single held row: count, then the newest hold's sender / reasons / expiry, then the key.
    pub fn row_text(&self, now: u64) -> Option<String> {
        if !self.row_visible() {
            return None;
        }
        let last = self.holds.last()?;
        let more = self.holds.len().saturating_sub(1);
        let extra = if more > 0 { format!(" (+{more} more)") } else { String::new() };
        Some(format!("{}{extra}  [{OPEN_KEY_HINT}] review", held_row_text(last, now)))
    }

    /// Record that `configure` is about to be sent for `sid`. `None`: already sent for this id, send nothing. `Some(closed)`:
    /// send it; `closed` when an open dialog had to be dropped (its tokens die with the new configure).
    pub fn note_configure(&mut self, sid: &str) -> Option<bool> {
        if self.configured_sid.as_deref() == Some(sid) {
            return None;
        }
        self.configured_sid = Some(sid.to_owned());
        Some(self.dialog.take().is_some())
    }

    pub fn dialog(&self) -> Option<&PeerHoldDialog> {
        self.dialog.as_ref().map(|d| &d.dialog)
    }

    pub fn dialog_open(&self) -> bool {
        self.dialog.is_some()
    }

    fn name_of(&self, id: &Option<String>) -> String {
        let Some(id) = id else { return String::new() };
        self.holds.iter().chain(self.recent.iter()).find(|h| &h.message_id == id).map(|h| h.from_name.clone()).unwrap_or_default()
    }

    fn remove(&mut self, id: &str) {
        if let Some(i) = self.holds.iter().position(|h| h.message_id == id) {
            let h = self.holds.remove(i);
            self.recent.retain(|r| r.message_id != id);
            self.recent.push_back(h);
            while self.recent.len() > RECENT_CAP {
                self.recent.pop_front();
            }
        }
        if self.dialog.as_ref().is_some_and(|d| d.dialog.is_for(id)) {
            self.dialog = None;
        }
    }

    /// Apply one event. Returns the one-line notice to show, if any. Flag off: nothing happens.
    pub fn apply_event(&mut self, ev: PeerEvent) -> Option<String> {
        self.apply_event_at(ev, now_secs())
    }

    /// [`apply_event`](Self::apply_event) with the clock given. A notice row is subject to the rate limit.
    pub(crate) fn apply_event_at(&mut self, ev: PeerEvent, now: u64) -> Option<String> {
        let line = self.apply_event_inner(ev)?;
        let (start, count, shown) = &mut self.notice_window;
        if now >= start.saturating_add(NOTICE_WINDOW_SECS) || now < *start {
            *start = now;
            *count = 0;
            *shown = false;
        }
        if *count < NOTICE_LIMIT {
            *count += 1;
            Some(line)
        } else if !*shown {
            *shown = true;
            Some(SUPPRESSED_NOTICE.to_owned())
        } else {
            None
        }
    }

    fn apply_event_inner(&mut self, ev: PeerEvent) -> Option<String> {
        if !peer_ui_enabled() {
            return None;
        }
        let gone = |s: &mut Self, id: Option<String>, make: fn(String) -> PeerNotice| {
            let name = s.name_of(&id);
            if let Some(id) = &id {
                s.remove(id);
            }
            notice_row_text(&make(name))
        };
        match ev {
            PeerEvent::Held(h) => {
                self.holds.retain(|x| x.message_id != h.message_id);
                self.holds.push(h);
                if self.holds.len() > MAX_HOLDS {
                    self.holds.remove(0);
                }
                None
            }
            PeerEvent::Released(id) => gone(self, id, |name| PeerNotice::Released { name }),
            PeerEvent::Refused(id) => gone(self, id, |name| PeerNotice::Refused { name }),
            PeerEvent::Expired(id) => gone(self, id, |name| PeerNotice::Expired { name }),
            PeerEvent::Reheld(id) => {
                let name = self.name_of(&id);
                if let Some(id) = id {
                    // Its old token is dead; the row returns (from what we last knew, or bare) and the dialog re-lists for a fresh one.
                    if !self.holds.iter().any(|h| h.message_id == id) {
                        let back = self.recent.iter().find(|h| h.message_id == id).cloned().unwrap_or_else(|| PeerHold {
                            message_id: id.clone(),
                            from_name: String::new(),
                            from_ref: String::new(),
                            sender_mode: String::new(),
                            own_mode: String::new(),
                            reasons: vec!["held_again".to_owned()],
                            denial_counts: Vec::new(),
                            expires_at_secs: now_secs() + 60,
                            first_line: String::new(),
                            detail: None,
                        });
                        self.holds.push(back);
                    }
                    if self.dialog.as_ref().is_some_and(|d| d.dialog.is_for(&id)) {
                        self.dialog = None;
                    }
                }
                notice_row_text(&PeerNotice::Reheld { name })
            }
            PeerEvent::Warning { text, subject } => notice_row_text(&PeerNotice::Warning { text, subject }),
        }
    }

    /// The list reply: the rows replace what the pager thought was held, and with `reopen` the first one opens in the dialog.
    /// Returns a line to show when there is nothing held.
    pub fn apply_list(&mut self, rows: Vec<(PeerHold, Token)>, open: bool) -> Option<String> {
        if !peer_ui_enabled() {
            return None;
        }
        self.dialog = None;
        for h in std::mem::take(&mut self.holds) {
            if !rows.iter().any(|(r, _)| r.message_id == h.message_id) {
                self.recent.push_back(h);
            }
        }
        while self.recent.len() > RECENT_CAP {
            self.recent.pop_front();
        }
        self.holds = rows.iter().map(|(h, _)| h.clone()).collect();
        if !open {
            return None;
        }
        match rows.into_iter().next() {
            None => Some("No peer message is held.".to_owned()),
            Some((hold, token)) => {
                self.dialog = PeerHoldDialog::open(hold).map(|dialog| OpenDialog { dialog, token });
                None
            }
        }
    }

    /// The decision succeeded: the row goes now (the shell's event gives the notice).
    pub fn note_decided(&mut self, held_id: &str) {
        self.remove(held_id);
    }

    /// Drop the open dialog and its token (another overlay took the screen or the keys). `true` if one was open.
    pub fn close_dialog(&mut self) -> bool {
        self.dialog.take().is_some()
    }

    /// A new frame starts (see `PeerHoldDialog::begin_frame`). No-op with no dialog.
    pub fn begin_frame(&self) {
        if let Some(d) = self.dialog.as_ref() {
            d.dialog.begin_frame();
        }
    }

    /// A non-key terminal event or full-screen clear was seen: the dialog's last paint is stale. No-op with no dialog.
    pub fn note_screen_disturbed(&self) {
        if let Some(d) = self.dialog.as_ref() {
            d.dialog.note_screen_disturbed();
        }
    }

    pub fn tick(&mut self, now: u64) {
        if let Some(d) = self.dialog.as_mut() {
            d.dialog.tick(now);
        }
    }

    /// A key while the dialog is open. Everything is swallowed (the prompt never sees it) except the dialog's own keys.
    /// Dismiss closes the dialog and drops its token.
    pub fn dialog_key(&mut self, key: &crossterm::event::KeyEvent) -> PeerDialogOutcome {
        let Some(d) = self.dialog.as_mut() else { return PeerDialogOutcome::Ignored };
        d.dialog.tick(now_secs());
        let out = d.dialog.handle_key(key);
        if out == PeerDialogOutcome::Dismiss {
            self.dialog = None;
        }
        out
    }

    /// Consume the dialog's token for the one decision. Closes the dialog. `None` when no dialog is open.
    pub fn take_decision(&mut self, refuse: bool) -> Option<PeerCall> {
        let d = self.dialog.take()?;
        Some(PeerCall::Decide { held_id: d.dialog.held_id().to_owned(), token: d.token, refuse })
    }
}

/// The fixed note line for a decision that the shell answered with something other than delivered / refused.
pub fn decision_note(result: &str) -> Option<String> {
    match result {
        "dropped" => Some("The held peer message was dropped at delivery; it was not added to this session.".to_owned()),
        "expired" => Some("That held peer message has expired.".to_owned()),
        _ => None,
    }
}

#[cfg(test)]
#[path = "peer_ui_state_tests.rs"]
mod tests;
