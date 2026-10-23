//! Peer messaging in the TUI (Fuigo 1.0.25, packet 12): the scrollback rows, the hold dialog, the influence marker.
//!
//! Everything here is behind `features.peer_messaging` ([`peer_ui_enabled`]); with it off no row, key or dialog exists.
//! A peer message is DATA: every peer-supplied string (name, ref, message text, reason) goes through
//! `fuigo_tty_utils` (`quoted` / `bracketed` / `capped`): control, bidi and zero-width characters are removed or escaped,
//! line breaks become spaces (so text can never forge a second row) and the length is capped. A preview shows the
//! FIRST LINE of the body only. Accepting a held message only releases the message; there is no key here that can approve a tool.

use std::time::Duration;

/// Fixed label of every preview row: it says where the text came from.
pub const PEER_ROW_LABEL: &str = "Message from another session";
/// Fixed sentence of the hold dialog.
pub const ACCEPT_SENTENCE: &str =
    "Accepting delivers the message to this session. It does not approve any tool call.";
/// The two fixed rows of the sentence (the dialog never wraps, so the sentence is split by Fuigo, not by a wrapper).
const ACCEPT_ROW_1: &str = "Accepting delivers the message to this session.";
const ACCEPT_ROW_2: &str = "It does not approve any tool call.";
/// Fixed legends (drawn in their own reserved row, never from peer text).
const LEGEND_LIVE: &str = "[a] accept  [r] refuse  [Esc] dismiss (stays held)";
const LEGEND_EXPIRED: &str = "[Esc] close";
/// Smallest dialog that can show one body row plus the fixed sentence and legend rows: below this `a` is not accepted.
pub const DIALOG_MIN_WIDTH: u16 = 52;
pub const DIALOG_MIN_HEIGHT: u16 = 6;
const DIALOG_MAX_WIDTH: u16 = 96;
const MAX_SHOWN_REASONS: usize = 4;
/// Fixed hint beside the influence marker.
pub const INFLUENCE_HINT: &str = "/peers clear-influence";

const NAME_COLS: usize = 40;
const REF_COLS: usize = 16;
const LINE_COLS: usize = 120;
const REASON_COLS: usize = 32;
const PATH_COLS: usize = 80;

#[cfg(test)]
thread_local! {
    static FLAG_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Test helper: force the flag on this thread. Restores on drop.
#[cfg(test)]
pub(crate) struct FlagGuard(Option<bool>);
#[cfg(test)]
impl Drop for FlagGuard {
    fn drop(&mut self) {
        FLAG_OVERRIDE.with(|c| c.set(self.0));
    }
}
#[cfg(test)]
pub(crate) fn force_peer_ui_for_test(on: bool) -> FlagGuard {
    FlagGuard(FLAG_OVERRIDE.with(|c| c.replace(Some(on))))
}

/// `features.peer_messaging` as the TUI sees it: requirements pin, environment, user config, default off.
/// (The remote tier is not read by the pager; a remote-only enablement leaves the TUI in today's shape.)
pub fn peer_ui_enabled() -> bool {
    #[cfg(test)]
    if let Some(forced) = FLAG_OVERRIDE.with(std::cell::Cell::get) {
        return forced;
    }
    static RESOLVED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *RESOLVED.get_or_init(|| {
        use fuigo_shell::agent::config::{Feature, FeatureSources};
        let key = Feature::PeerMessaging.key();
        let layer_value = |layer: Option<toml::Value>| layer?.get("features")?.get(key)?.as_bool();
        let mut sources = FeatureSources::from_process_env(Feature::PeerMessaging);
        sources.pin = layer_value(fuigo_config::load_merged_requirements());
        sources.config = layer_value(fuigo_shell::config::load_effective_config().ok());
        Feature::PeerMessaging.resolve(sources).value
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------------------------------------------------

/// A peer-supplied session name as one quoted, capped, single-line field.
pub fn name_field(name: &str) -> String {
    if name.is_empty() {
        "(unnamed)".to_owned()
    } else {
        fuigo_tty_utils::quoted(name, NAME_COLS)
    }
}

/// A peer-supplied `[ref]`.
pub fn ref_field(r: &str) -> String {
    fuigo_tty_utils::bracketed(r, REF_COLS)
}

/// The first line of a message body, quoted and capped. A line break of any kind (LF, CR, NEL, U+2028, U+2029) ends it.
pub fn first_line_field(body: &str) -> String {
    let end = body
        .find(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
        .unwrap_or(body.len());
    fuigo_tty_utils::quoted(&body[..end], LINE_COLS)
}

pub(crate) fn text_field(s: &str, cols: usize) -> String {
    fuigo_tty_utils::capped(s, cols)
}

// ---------------------------------------------------------------------------------------------------------------------
// Parsing the delivered message (the wrapper the shell builds in `wrap_peer_message`)
// ---------------------------------------------------------------------------------------------------------------------

/// What the delivery row shows about one delivered peer message. Raw (unescaped) claims: every use goes through the fields above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredPeerMessage {
    pub from_name: String,
    pub from_ref: String,
    pub message_id: String,
    pub body_first_line: String,
}

fn unescape_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(semi) = rest.find(';').filter(|&j| j <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..semi];
        let ch = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "#39" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn attr<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!(" {name}=\"");
    let start = header.find(&pat)? + pat.len();
    let len = header[start..].find('"')?;
    Some(&header[start..start + len])
}

/// Parse the model-facing wrapper of a delivered peer message. `None` when the text is not exactly that shape.
pub fn parse_delivered(wrapped: &str) -> Option<DeliveredPeerMessage> {
    const OPEN: &str = "<cross-session-message ";
    const CLOSE: &str = "</cross-session-message>";
    let open = wrapped.find(OPEN)?;
    let after = &wrapped[open..];
    let gt = after.find('>')?;
    let header = &after[..gt];
    let body = &after[gt + 1..];
    let body = body.strip_prefix('\n').unwrap_or(body);
    let body = body.rfind(CLOSE).map_or(body, |i| &body[..i]);
    // The first raw line break ends the preview line; entities are decoded after the cut so a decoded U+2028 stays inside it
    // and is then scrubbed by the filter.
    let end = body.find('\n').unwrap_or(body.len());
    Some(DeliveredPeerMessage {
        from_name: unescape_entities(attr(header, "from-name")?),
        from_ref: unescape_entities(attr(header, "from-ref")?),
        message_id: unescape_entities(attr(header, "message-id")?),
        body_first_line: unescape_entities(&body[..end]),
    })
}

// ---------------------------------------------------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------------------------------------------------

/// The ONE scrollback row for a delivered peer message: fixed label, escaped name and ref, escaped first line.
pub fn preview_row_text(m: &DeliveredPeerMessage) -> String {
    format!(
        "\u{21aa} {PEER_ROW_LABEL} {} {}: {}",
        name_field(&m.from_name),
        ref_field(&m.from_ref),
        first_line_field(&m.body_first_line)
    )
}

/// Row text for a wrapped delivered message, or `None` (flag off, or not a peer wrapper: the caller keeps today's row).
pub fn preview_row_for_wrapped(wrapped: &str) -> Option<String> {
    if !peer_ui_enabled() {
        return None;
    }
    parse_delivered(wrapped).map(|m| preview_row_text(&m))
}

/// One held message, as the hold row and the dialog show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHold {
    pub message_id: String,
    pub from_name: String,
    pub from_ref: String,
    /// The mode the sender reports (its claim).
    pub sender_mode: String,
    /// This session's mode.
    pub own_mode: String,
    /// Reason names as the shell reports them (`mode_mismatch`, `sender_denied`, `integrity`, ...).
    pub reasons: Vec<String>,
    /// For a `sender_denied` hold: tool kind and count only (S7.2), never targets.
    pub denial_counts: Vec<(String, u32)>,
    /// Wall-clock seconds at which the hold expires.
    pub expires_at_secs: u64,
    /// First line of the body (raw; escaped when drawn).
    pub first_line: String,
    /// The shell's own (already escaped) note for the hold, e.g. what a `sender_denied` hold was denied (12b). Untrusted: capped when drawn.
    pub detail: Option<String>,
}

/// Pager-owned label for a reason name the shell sends (`hold_name` in fuigo-shell). Anything else is `other`: a peer-chosen
/// string is never printed as a reason.
fn reason_label(name: &str) -> &'static str {
    match name {
        "mode_mismatch" => "mode mismatch",
        "loop_guard" => "loop guard",
        "sender_denied" => "sender denied",
        "integrity" => "integrity",
        "policy_hold" => "policy hold",
        "held_again" => "held again",
        _ => "other",
    }
}

/// Display columns of one grapheme cluster. Never under-measures: the larger of Fuigo's and the unicode table's width, and a
/// multi-scalar non-ASCII cluster (emoji + U+FE0F, a ZWJ sequence, a flag pair) counts at least 2.
fn cluster_width(g: &str) -> usize {
    use unicode_width::UnicodeWidthStr;
    let w = fuigo_tty_utils::display_width(g).max(UnicodeWidthStr::width(g));
    if g.chars().nth(1).is_some() && !g.is_ascii() {
        w.max(2)
    } else {
        w
    }
}

/// Display width of `s` measured by grapheme cluster (see [`cluster_width`]).
pub(crate) fn line_width(s: &str) -> usize {
    use unicode_segmentation::UnicodeSegmentation;
    s.graphemes(true).map(cluster_width).sum()
}

/// `s` cut to `cols` display columns with a trailing ellipsis (never wrapped; cut by grapheme cluster, so a cluster is never split and
/// the result never measures wider than `cols`).
pub(crate) fn fit_line(s: &str, cols: usize) -> String {
    use unicode_segmentation::UnicodeSegmentation;
    if line_width(s) <= cols {
        return s.to_owned();
    }
    let mut out = String::new();
    let mut w = 0;
    for g in s.graphemes(true) {
        let cw = cluster_width(g);
        if w + cw + 1 > cols {
            break;
        }
        w += cw;
        out.push_str(g);
    }
    if cols > 0 {
        out.push('\u{2026}');
    }
    out
}

impl PeerHold {
    fn reasons_text(&self) -> String {
        let mut parts: Vec<&str> = self
            .reasons
            .iter()
            .take(MAX_SHOWN_REASONS)
            .map(|r| reason_label(r))
            .collect();
        if parts.is_empty() {
            parts.push("other");
        }
        let mut s = parts.join(", ");
        if self.reasons.len() > MAX_SHOWN_REASONS {
            s.push_str(&format!(", +{}", self.reasons.len() - MAX_SHOWN_REASONS));
        }
        s
    }

    /// The quoted-denial note; `cols` caps the quoted peer value.
    fn denial_text(&self, cols: usize) -> Option<String> {
        if self.denial_counts.is_empty() {
            // 12b: the wire carries the shell's note instead of counts; show it for a `sender_denied` hold only.
            let d = self
                .detail
                .as_deref()
                .filter(|d| !d.is_empty() && self.reasons.iter().any(|r| r == "sender_denied"))?;
            return Some(format!(
                "the sender was recently denied: {}",
                fuigo_tty_utils::quoted(d, cols.min(LINE_COLS))
            ));
        }
        let parts: Vec<String> = self
            .denial_counts
            .iter()
            .map(|(k, n)| format!("{} x{n}", fuigo_tty_utils::quoted(k, REASON_COLS)))
            .collect();
        Some(format!(
            "the sender was recently denied: {}",
            parts.join(", ")
        ))
    }
}

fn expiry_text(expires_at_secs: u64, now_secs: u64) -> String {
    match expires_at_secs.checked_sub(now_secs) {
        Some(left) if left > 0 => format!("expires in {left}s"),
        _ => "expired".to_owned(),
    }
}

/// The ONE scrollback row for a held message: sender, reasons, kinds and counts for a `sender_denied` hold, expiry.
pub fn held_row_text(h: &PeerHold, now_secs: u64) -> String {
    let mut s = format!(
        "\u{23f8} A message from {} {} is held: {}",
        name_field(&h.from_name),
        ref_field(&h.from_ref),
        h.reasons_text()
    );
    if let Some(d) = h.denial_text(LINE_COLS) {
        s.push_str("; ");
        s.push_str(&d);
    }
    s.push_str("; ");
    s.push_str(&expiry_text(h.expires_at_secs, now_secs));
    s
}

/// What a notice row is about. The row is fixed text plus escaped names; a peer string is never a whole row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerNotice {
    Delivered {
        name: String,
    },
    Released {
        name: String,
    },
    Refused {
        name: String,
        told: bool,
    },
    Expired {
        name: String,
    },
    /// A protected file changed while peer-influenced (packet 6).
    IntegrityWarning {
        path: String,
    },
    /// A request matching a denial the sender carried was refused (packet 7).
    LaunderingRefused {
        name: String,
    },
    /// A released message could not be delivered yet and is held again (12b).
    Reheld {
        name: String,
    },
    /// A `peer_warning` event: the shell's fixed text and an escaped subject, both capped again here (12b).
    Warning {
        text: String,
        subject: String,
    },
}

/// The system notice row for one notice. `None` when the flag is off.
pub fn notice_row_text(n: &PeerNotice) -> Option<String> {
    if !peer_ui_enabled() {
        return None;
    }
    Some(match n {
        PeerNotice::Delivered { name } => format!(
            "Peer message from {} was delivered to this session.",
            name_field(name)
        ),
        PeerNotice::Released { name } => {
            format!(
                "Held peer message from {} was released. No tool call was approved.",
                name_field(name)
            )
        }
        PeerNotice::Refused { name, told } => {
            format!(
                "Peer message from {} was refused{}",
                name_field(name),
                if *told { "; the sender is told." } else { "." }
            )
        }
        PeerNotice::Expired { name } => format!(
            "Held peer message from {} expired and was dropped.",
            name_field(name)
        ),
        PeerNotice::IntegrityWarning { path } => format!(
            "Warning: a protected file changed while this session was peer-influenced: {}. Peer messages are held until you review it.",
            fuigo_tty_utils::quoted(path, PATH_COLS)
        ),
        PeerNotice::LaunderingRefused { name } => format!(
            "A request matching an action you denied was refused: it came through a message from {}.",
            name_field(name)
        ),
        PeerNotice::Reheld { name } => {
            format!(
                "Held peer message from {} could not be delivered yet and is held again.",
                name_field(name)
            )
        }
        PeerNotice::Warning { text, subject } => {
            let subject = fuigo_tty_utils::quoted(subject, PATH_COLS);
            let text = fuigo_tty_utils::quoted(text, LINE_COLS);
            format!(
                "Warning from a peer notice: {text}{}",
                if subject == "\"\"" {
                    String::new()
                } else {
                    format!(" about {subject}")
                }
            )
        }
    })
}

/// The persistent status-area indicator while the session is peer-influenced; `None` otherwise or with the flag off.
pub fn influence_marker_text(influenced: bool) -> Option<String> {
    (peer_ui_enabled() && influenced).then(|| format!("peer-influenced  {INFLUENCE_HINT}"))
}

// ---------------------------------------------------------------------------------------------------------------------
// Hold dialog
// ---------------------------------------------------------------------------------------------------------------------

/// What a key in the hold dialog asks the app to do. The command is the ONLY thing sent: the same text the human could
/// type. There is no variant that approves a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDialogOutcome {
    /// Key not used by the dialog.
    Ignored,
    /// Dialog stays open, redraw.
    Changed,
    /// Release this message (`_fuigo/peer/release`), close the dialog.
    Release,
    /// Refuse this message, close the dialog.
    Refuse,
    /// Close; the message stays held.
    Dismiss,
}

/// The dialog for one held message. Opened only by the human at the keyboard.
#[derive(Debug, Clone)]
pub struct PeerHoldDialog {
    hold: PeerHold,
    expired: bool,
    /// FRESHNESS: true only if the most recent frame painted the fixed sentence and legend entirely inside the rect used, and no
    /// resize has been seen since. Starts false; cleared at the start of every frame ([`Self::begin_frame`]) and by every
    /// `Event::Resize` ([`Self::note_screen_disturbed`]). `a` is accepted only while it is true.
    fits: std::cell::Cell<bool>,
}

fn id_is_plain(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

impl PeerHoldDialog {
    /// Open the dialog. `None` with the flag off, or when the message id is not a plain token (it is put in a command).
    pub fn open(hold: PeerHold) -> Option<Self> {
        (peer_ui_enabled() && id_is_plain(&hold.message_id)).then_some(Self {
            hold,
            expired: false,
            fits: std::cell::Cell::new(false),
        })
    }

    pub fn message_id(&self) -> &str {
        &self.hold.message_id
    }

    pub fn is_expired(&self) -> bool {
        self.expired
    }

    /// Time passes: at the deadline the dialog shows "expired" and accept / refuse stop sending anything.
    pub fn tick(&mut self, now_secs: u64) -> bool {
        let was = self.expired;
        self.expired = now_secs >= self.hold.expires_at_secs;
        was != self.expired
    }

    /// The hold was released or refused elsewhere (`/peers ...`) or dropped: close.
    pub fn is_for(&self, message_id: &str) -> bool {
        self.hold.message_id == message_id
    }

    /// The message id (the opaque `heldId` since 12b).
    pub fn held_id(&self) -> &str {
        &self.hold.message_id
    }

    /// `a` accepts (release), `r` refuses, `Esc` / `d` / `q` dismiss. Enter does nothing, so a stray Enter never releases.
    pub fn handle_key(&mut self, key: &crossterm::event::KeyEvent) -> PeerDialogOutcome {
        use crossterm::event::{KeyCode, KeyModifiers};
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return PeerDialogOutcome::Ignored;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('d' | 'q') => PeerDialogOutcome::Dismiss,
            _ if self.expired => PeerDialogOutcome::Ignored,
            KeyCode::Char('a') if !self.fits.get() => PeerDialogOutcome::Ignored,
            KeyCode::Char('a') => PeerDialogOutcome::Release,
            KeyCode::Char('r') => PeerDialogOutcome::Refuse,
            _ => PeerDialogOutcome::Ignored,
        }
    }

    /// The peer-derived and status rows, ONE line each, every peer value quoted or bracketed after a fixed label and cut to
    /// `width` columns (never wrapped). Pure; the renderer paints these above the fixed rows.
    pub fn body_lines(&self, now_secs: u64, width: usize) -> Vec<String> {
        let h = &self.hold;
        let q = |label: &str, v: &str, cap: usize| {
            let cols = width
                .saturating_sub(label.chars().count() + 2)
                .clamp(1, cap);
            fit_line(
                &format!("{label}{}", fuigo_tty_utils::quoted(v, cols)),
                width,
            )
        };
        let name = if h.from_name.is_empty() {
            "(unnamed)".to_owned()
        } else {
            h.from_name.clone()
        };
        let mut v = vec![fit_line(
            &format!(
                "From: {} {}",
                fuigo_tty_utils::quoted(&name, NAME_COLS.min(width.saturating_sub(24).max(1))),
                fuigo_tty_utils::bracketed(
                    &h.from_ref,
                    REF_COLS.min(width.saturating_sub(24).max(1))
                )
            ),
            width,
        )];
        v.push(q("Sender mode (its claim): ", &h.sender_mode, REASON_COLS));
        // 12b: the wire does not carry this session's own mode or the body; an empty field is left out, never invented.
        if !h.own_mode.is_empty() {
            v.push(q("This session's mode: ", &h.own_mode, REASON_COLS));
        }
        v.push(fit_line(
            &format!("Held because: {}", h.reasons_text()),
            width,
        ));
        if let Some(d) = h.denial_text(width.saturating_sub(40).max(1)) {
            v.push(fit_line(&format!("Note: {d}"), width));
        }
        if !h.first_line.is_empty() {
            v.push(q(
                "Starts: ",
                &h.first_line[..h
                    .first_line
                    .find(['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'])
                    .unwrap_or(h.first_line.len())],
                LINE_COLS,
            ));
        }
        v.push(if self.expired {
            "This hold has expired.".to_owned()
        } else {
            expiry_text(h.expires_at_secs, now_secs)
        });
        v
    }

    /// The Fuigo-owned rows pinned to the bottom of the box: sentence (two rows) and the legend. No peer text.
    pub fn fixed_lines(&self) -> [&'static str; 3] {
        [
            ACCEPT_ROW_1,
            ACCEPT_ROW_2,
            if self.expired {
                LEGEND_EXPIRED
            } else {
                LEGEND_LIVE
            },
        ]
    }

    /// All rows top to bottom (body, then the fixed rows).
    pub fn lines(&self, now_secs: u64, width: usize) -> Vec<String> {
        let mut v = self.body_lines(now_secs, width);
        v.extend(self.fixed_lines().iter().map(|s| (*s).to_owned()));
        v
    }

    /// A new frame starts: nothing has been painted yet, so `a` waits for this frame's paint.
    pub fn begin_frame(&self) {
        self.fits.set(false);
    }

    /// The screen was disturbed (resize, focus, mouse, paste, full clear/heal, mode switch, child suspend): the last paint no longer describes it.
    pub fn note_screen_disturbed(&self) {
        self.fits.set(false);
    }

    /// Whether the last frame painted the fixed sentence and legend and no resize came since (what lets `a` act).
    pub fn fits(&self) -> bool {
        self.fits.get()
    }
}

/// Paint the dialog centered in `area`. FIXED layout: border, body rows (single lines, clipped by count never wrapped), then the
/// sentence (2 rows) and the legend pinned to the last three inner rows. Too small for those: one "terminal too small" line and
/// `a` is not accepted.
pub fn render_peer_hold_dialog(
    area: ratatui::layout::Rect,
    buf: &mut ratatui::buffer::Buffer,
    d: &PeerHoldDialog,
    now_secs: u64,
) {
    use ratatui::layout::Rect;
    use ratatui::style::Style;
    use ratatui::widgets::{Block, Borders, Clear, Widget};
    let theme = crate::theme::Theme::current();
    let style = Style::default().bg(theme.bg_dark);
    let w = area.width.min(DIALOG_MAX_WIDTH);
    if w < DIALOG_MIN_WIDTH || area.height < DIALOG_MIN_HEIGHT {
        d.fits.set(false);
        if area.width == 0 || area.height == 0 {
            return;
        }
        let msg = fit_line(
            "Terminal too small to accept. Enlarge it. (r refuses, Esc dismisses)",
            area.width as usize,
        );
        let y = area.y + area.height / 2;
        Clear.render(Rect::new(area.x, y, area.width, 1), buf);
        buf.set_stringn(area.x, y, &msg, area.width as usize, style);
        return;
    }
    let iw = (w - 2) as usize;
    let body = d.body_lines(now_secs, iw);
    let h = (body.len() as u16 + 5).clamp(DIALOG_MIN_HEIGHT, area.height);
    let rect = Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    );
    // The fixed rows must lie entirely inside the buffer that is actually flushed.
    if buf.area.intersection(rect) != rect || rect.height < DIALOG_MIN_HEIGHT {
        d.fits.set(false);
        return;
    }
    Clear.render(rect, buf);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Peer message held ")
        .style(style);
    let inner = block.inner(rect);
    block.render(rect, buf);
    let body_rows = (inner.height - 3) as usize;
    for (i, line) in body.iter().take(body_rows).enumerate() {
        buf.set_stringn(inner.x, inner.y + i as u16, line, iw, style);
    }
    for (i, line) in d.fixed_lines().iter().enumerate() {
        buf.set_stringn(
            inner.x,
            inner.y + inner.height - 3 + i as u16,
            line,
            iw,
            style,
        );
    }
    // Last: only now were the sentence and legend painted inside the rect used.
    d.fits.set(true);
}

/// Seconds since the epoch, for the dialog clock.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

#[cfg(test)]
#[path = "peer_ui_tests.rs"]
mod tests;
