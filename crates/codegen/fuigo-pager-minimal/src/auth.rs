//! Minimal-mode sign-in / folder-trust rendering for the live region.
//!
//! Minimal has no welcome screen, so before any agent session exists the live region shows the sign-in flow itself.
//! [`draw_live`](super::live::draw_live) maps [`AuthState`] and [`TrustState`] to a [`MinimalAuthHint`] and renders it via [`render_auth`].

use std::path::PathBuf;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use fuigo_pager::app::app_view::{AuthState, TrustState};
use fuigo_pager::theme::Theme;

/// What the minimal live region shows when there is no active agent yet.
/// Computed before the draw closure so the closure can own it.
pub(super) enum MinimalAuthHint {
    /// Interactive sign-in underway: show the URL (when known) and the device code (when the URL carries one).
    /// Covers device flow and the external command flow, where the provider opens its own browser and `url` may be `None`.
    SigningIn {
        url: Option<String>,
        code: Option<String>,
    },
    /// The last sign-in attempt failed; show the error.
    Failed(String),
    /// Authenticated, but the cwd has untrusted repo-local config: ask before creating a session.
    /// Input (y/Enter trust, n/Esc quit) is handled by the welcome interceptor in `AppView::handle_input`; this is render-only.
    /// `error`: why the last "yes" recorded nothing (P167), shown under the question until it is answered.
    TrustFolder { workspace: PathBuf, error: Option<String> },
    /// Authenticated and trusted; the session is being created (brief transient).
    Starting,
}

/// Map the app's auth and trust state to what the no-agent live region should show.
///
/// Mirrors the welcome screen's gate order: trust is only offered after auth is `Done`, when the user has access and is not ZDR-blocked.
/// Those gates already block sessions, and the input interceptor only answers trust under the same conditions.
pub(super) fn minimal_auth_hint(
    auth: &AuthState,
    trust: &TrustState,
    has_access: bool,
    is_zdr_blocked: bool,
    trust_error: Option<&str>,
) -> MinimalAuthHint {
    match auth {
        AuthState::Authenticating { auth_url, .. } => MinimalAuthHint::SigningIn {
            url: auth_url.clone(),
            code: auth_url
                .as_deref()
                .and_then(device_user_code)
                .map(str::to_owned),
        },
        AuthState::Pending { error: Some(err) } => MinimalAuthHint::Failed(err.clone()),
        // Login is starting (auto-triggered at startup); the URL arrives via AuthUrlReady, which flips us to `Authenticating`
        AuthState::Pending { error: None } => MinimalAuthHint::SigningIn {
            url: None,
            code: None,
        },
        AuthState::Done if has_access && !is_zdr_blocked => {
            if let TrustState::Pending { workspace } = trust {
                MinimalAuthHint::TrustFolder {
                    workspace: workspace.clone(),
                    error: trust_error.map(str::to_owned),
                }
            } else {
                MinimalAuthHint::Starting
            }
        }
        AuthState::Done => MinimalAuthHint::Starting,
    }
}

/// Rows the no-agent live region needs for `hint` (before path wrap).
/// Used by the overlay host so the viewport grows enough to show the trust question instead of clipping to the idle prompt height.
pub(super) fn auth_hint_rows(hint: &MinimalAuthHint, width: u16) -> u16 {
    match hint {
        // header + blank + "Opening browser…"
        MinimalAuthHint::SigningIn { url: None, code: _ } => 3,
        // header + blank + "Open this URL" + url rows + optional code block + blank + "Waiting…"
        MinimalAuthHint::SigningIn {
            url: Some(url),
            code,
        } => {
            let url_rows = wrapped_char_rows(url, width, Shown::UrlBytes);
            let code_rows = if code.is_some() { 2 } else { 0 }; // blank + "Code: …"
            3 + url_rows + code_rows + 2
        }
        // "Sign-in failed" + blank + error
        MinimalAuthHint::Failed(_) => 3,
        // question + path rows + blank + 2 warning + blank + 2 menu + blank + hint
        MinimalAuthHint::TrustFolder { workspace, error } => {
            let path = workspace.display().to_string();
            let path_rows = wrapped_char_rows(&path, width, Shown::Placeholder);
            // + blank + wrapped error, when the last "yes" recorded nothing
            let error_rows = error.as_deref().map_or(0, |e| 1 + wrapped_char_rows(e, width, Shown::Placeholder));
            1 + path_rows + error_rows + 1 + 2 + 1 + 2 + 1 + 1
        }
        MinimalAuthHint::Starting => 1,
    }
}

/// How unsafe characters in painted text show.
#[derive(Clone, Copy)]
enum Shown {
    /// A URL: percent-encoded bytes, so a copy keeps what the original said.
    UrlBytes,
    /// A path or message: one visible placeholder each. Percent bytes would read as part of a real name.
    Placeholder,
}

impl Shown {
    fn of(self, text: &str) -> std::borrow::Cow<'_, str> {
        match self {
            Shown::UrlBytes => fuigo_tty_utils::escape_unsafe_display(text),
            Shown::Placeholder => fuigo_tty_utils::replace_unsafe_display(text, '\u{FFFD}'),
        }
    }
}

/// How many rows `text` needs when painted char-by-char at `width` (no wrap-inserted spaces); same layout as [`render_url`].
fn wrapped_char_rows(text: &str, width: u16, shown: Shown) -> u16 {
    let width = width.max(1) as usize;
    let chars = shown.of(text).chars().count();
    if chars == 0 {
        return 1;
    }
    chars.div_ceil(width) as u16
}

/// Parse the device-flow `user_code` from a verification URL (`None` if absent or malformed).
/// Mirrors `views::welcome::extract_user_code`, kept local so minimal does not depend on welcome-screen internals.
fn device_user_code(url: &str) -> Option<&str> {
    let code = url
        .split('?')
        .nth(1)?
        .split('&')
        .find_map(|kv| kv.strip_prefix("user_code="))?;
    (!code.is_empty() && code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        .then_some(code)
}

/// Write `line` at row `y` (when it fits) and return the next row.
fn put_line(buf: &mut Buffer, area: Rect, y: u16, bottom: u16, line: Line<'_>) -> u16 {
    if y < bottom {
        buf.set_line(area.x, y, &line, area.width);
        y + 1
    } else {
        y
    }
}

/// Write `url` char-by-char across as many rows as it needs (no wrap-inserted spaces), so the terminal's native selection copies it verbatim.
/// Minimal has no mouse capture, so copy is the terminal's job.
/// Returns the next free row.
fn render_url(
    buf: &mut Buffer,
    area: Rect,
    start_y: u16,
    bottom: u16,
    url: &str,
    style: Style,
    shown: Shown,
) -> u16 {
    let width = area.width.max(1);
    // Snapshot the buffer bounds as values so the `&Rect` borrow doesn't outlive the mutable cell writes below
    let (max_x, max_y) = {
        let a = buf.area();
        (a.right(), a.bottom())
    };
    let mut col = 0u16;
    let mut y = start_y;
    // Control characters and invisible format characters show as percent bytes: no escape reaches the terminal, and a
    // copy of the painted text keeps what the original said
    for ch in shown.of(url).chars() {
        if col >= width {
            col = 0;
            y = y.saturating_add(1);
        }
        if y >= bottom {
            return bottom;
        }
        let x = area.x + col;
        if x < max_x && y < max_y {
            buf[(x, y)].set_char(ch).set_style(style);
        }
        col += 1;
    }
    y.saturating_add(1)
}

/// Render the sign-in / trust flow (or transient status) in the live region when no agent exists yet.
/// Top-aligned in `area`; clips to its height.
pub(super) fn render_auth(buf: &mut Buffer, area: Rect, theme: &Theme, hint: &MinimalAuthHint) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let bottom = area.y + area.height;
    let mut y = area.y;
    let gray = theme.muted().bg(Color::Reset);
    let bold = Style::default()
        .fg(theme.text_primary)
        .add_modifier(Modifier::BOLD)
        .bg(Color::Reset);

    match hint {
        MinimalAuthHint::SigningIn { url, code } => {
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled("Sign in to Fuigo", bold)),
            );
            y = put_line(buf, area, y, bottom, Line::default());
            match url {
                Some(url) => {
                    y = put_line(
                        buf,
                        area,
                        y,
                        bottom,
                        Line::from(Span::styled(
                            "Open this URL in your browser to approve:",
                            gray,
                        )),
                    );
                    y = render_url(
                        buf,
                        area,
                        y,
                        bottom,
                        url,
                        Style::default().fg(theme.accent_user).bg(Color::Reset),
                        Shown::UrlBytes,
                    );
                    if let Some(code) = code {
                        y = put_line(buf, area, y, bottom, Line::default());
                        y = put_line(
                            buf,
                            area,
                            y,
                            bottom,
                            Line::from(vec![
                                Span::styled("Code: ", gray),
                                Span::styled(code.clone(), bold),
                            ]),
                        );
                    }
                    y = put_line(buf, area, y, bottom, Line::default());
                    let _ = put_line(
                        buf,
                        area,
                        y,
                        bottom,
                        Line::from(Span::styled("Waiting for approval\u{2026}", gray)),
                    );
                }
                None => {
                    let _ = put_line(
                        buf,
                        area,
                        y,
                        bottom,
                        Line::from(Span::styled(
                            "Opening your browser to sign in\u{2026}",
                            gray,
                        )),
                    );
                }
            }
        }
        MinimalAuthHint::Failed(err) => {
            let warn = Style::default()
                .fg(theme.warning)
                .add_modifier(Modifier::BOLD)
                .bg(Color::Reset);
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled("Sign-in failed", warn)),
            );
            y = put_line(buf, area, y, bottom, Line::default());
            let _ = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled(err.clone(), gray)),
            );
        }
        MinimalAuthHint::TrustFolder { workspace, error } => {
            // Mirrors `render_welcome_trust` copy, flush-left for minimal.
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled(
                    "Do you trust the contents of this directory?",
                    bold,
                )),
            );
            y = render_url(
                buf,
                area,
                y,
                bottom,
                &workspace.display().to_string(),
                Style::default().fg(theme.accent_user).bg(Color::Reset),
                Shown::Placeholder,
            );
            // P167: the last "yes" recorded nothing; say why, here, since the minimal view paints no welcome toast.
            if let Some(err) = error {
                y = put_line(buf, area, y, bottom, Line::default());
                y = render_url(
                    buf,
                    area,
                    y,
                    bottom,
                    err,
                    Style::default().fg(theme.accent_error).bg(Color::Reset),
                    Shown::Placeholder,
                );
            }
            y = put_line(buf, area, y, bottom, Line::default());
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled(
                    "Fuigo may run or modify contents in this directory,",
                    gray,
                )),
            );
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled("posing security risks.", gray)),
            );
            y = put_line(buf, area, y, bottom, Line::default());
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(vec![
                    Span::styled("y", bold),
                    Span::styled("  Yes, proceed", gray),
                ]),
            );
            y = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(vec![
                    Span::styled("n", bold),
                    Span::styled("  No, quit", gray),
                ]),
            );
            y = put_line(buf, area, y, bottom, Line::default());
            let _ = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled(
                    "Enter or y to trust \u{00b7} n or Esc to quit",
                    gray,
                )),
            );
        }
        MinimalAuthHint::Starting => {
            let _ = put_line(
                buf,
                area,
                y,
                bottom,
                Line::from(Span::styled(
                    "Signing in\u{2026} starting your session.",
                    gray,
                )),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P181: tag characters, soft hyphens and line separators show as percent bytes, and the row count follows.
    #[test]
    fn url_painting_shows_hidden_characters_as_percent_bytes() {
        let dirty = "https://a\u{00ad}.example/\u{e0041}x\u{2028}y\x1b";
        let shown = "https://a%C2%AD.example/%F3%A0%81%81x%E2%80%A8y%1B";
        assert_eq!(
            usize::from(wrapped_char_rows(dirty, 20, Shown::UrlBytes)),
            shown.chars().count().div_ceil(20)
        );
        let area = Rect::new(0, 0, 60, 3);
        let mut buf = Buffer::empty(area);
        render_url(&mut buf, area, 0, 3, dirty, Style::default(), Shown::UrlBytes);
        let row: String = (0..60).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        assert_eq!(row.trim_end(), shown);
    }

    /// P181 (Astra round 2): a path or message is not a URL; its hidden characters show as one placeholder each, never as
    /// percent bytes that would read as part of a real name.
    #[test]
    fn path_painting_shows_hidden_characters_as_a_placeholder() {
        let area = Rect::new(0, 0, 40, 3);
        let mut buf = Buffer::empty(area);
        render_url(&mut buf, area, 0, 3, "/tmp/a\u{00ad}b\u{e0041}c", Style::default(), Shown::Placeholder);
        let row: String = (0..40).map(|x| buf[(x, 0)].symbol().to_string()).collect();
        assert_eq!(row.trim_end(), "/tmp/a\u{fffd}b\u{fffd}c");
        assert_eq!(wrapped_char_rows("/tmp/a\u{00ad}b\u{e0041}c", 5, Shown::Placeholder), 2);
    }

    #[test]
    fn device_user_code_parses_verification_url() {
        assert_eq!(
            device_user_code("https://accounts.x.ai/oauth2/device?user_code=ABCD-EFGH"),
            Some("ABCD-EFGH")
        );
        assert_eq!(
            device_user_code("https://accounts.x.ai/oauth2/device"),
            None
        );
        assert_eq!(device_user_code("https://x/device?other=1"), None);
    }

    #[test]
    fn auth_hint_maps_auth_state() {
        use fuigo_pager::app::app_view::AuthMode;

        let trust_done = TrustState::Done;

        // Device flow maps to SigningIn carrying the URL and the parsed code
        let st = AuthState::Authenticating {
            request_seq: 1,
            handle: None,
            auth_url: Some("https://accounts.x.ai/device?user_code=ABCD-EFGH".into()),
            mode: AuthMode::Device,
        };
        match minimal_auth_hint(&st, &trust_done, true, false, None) {
            MinimalAuthHint::SigningIn { url, code } => {
                assert_eq!(
                    url.as_deref(),
                    Some("https://accounts.x.ai/device?user_code=ABCD-EFGH")
                );
                assert_eq!(code.as_deref(), Some("ABCD-EFGH"));
            }
            _ => panic!("expected SigningIn"),
        }

        // External command flow maps to SigningIn with the URL and no code
        let st = AuthState::Authenticating {
            request_seq: 2,
            handle: None,
            auth_url: Some("https://provider.example/login".into()),
            mode: AuthMode::Command,
        };
        match minimal_auth_hint(&st, &trust_done, true, false, None) {
            MinimalAuthHint::SigningIn { url, code } => {
                assert_eq!(url.as_deref(), Some("https://provider.example/login"));
                assert!(code.is_none());
            }
            _ => panic!("expected SigningIn"),
        }

        assert!(matches!(
            minimal_auth_hint(&AuthState::Done, &trust_done, true, false, None),
            MinimalAuthHint::Starting
        ));
        assert!(matches!(
            minimal_auth_hint(
                &AuthState::Pending {
                    error: Some("nope".into())
                },
                &trust_done,
                true,
                false,
                None
            ),
            MinimalAuthHint::Failed(_)
        ));
    }

    #[test]
    fn auth_hint_maps_pending_trust_after_auth() {
        let trust = TrustState::Pending {
            workspace: PathBuf::from("/tmp/untrusted-repo"),
        };
        match minimal_auth_hint(&AuthState::Done, &trust, true, false, None) {
            MinimalAuthHint::TrustFolder { workspace, error } => {
                assert_eq!(workspace, PathBuf::from("/tmp/untrusted-repo"));
                assert_eq!(error, None);
            }
            _ => panic!("expected TrustFolder"),
        }

        // Access / ZDR gates suppress the trust question (matches welcome and the input interceptor)
        assert!(matches!(
            minimal_auth_hint(&AuthState::Done, &trust, false, false, None),
            MinimalAuthHint::Starting
        ));
        assert!(matches!(
            minimal_auth_hint(&AuthState::Done, &trust, true, true, None),
            MinimalAuthHint::Starting
        ));

        // Trust is not offered while auth is still in flight.
        assert!(matches!(
            minimal_auth_hint(&AuthState::Pending { error: None }, &trust, true, false, None),
            MinimalAuthHint::SigningIn { .. }
        ));
    }

    #[test]
    fn render_auth_shows_url_and_code() {
        let _theme = fuigo_pager::theme::cache::pin_theme();
        let theme = Theme::current();
        let area = Rect::new(0, 0, 80, 12);
        let mut buf = Buffer::empty(area);
        let hint = MinimalAuthHint::SigningIn {
            url: Some("https://accounts.x.ai/device?user_code=ABCD-EFGH".into()),
            code: Some("ABCD-EFGH".into()),
        };
        render_auth(&mut buf, area, &theme, &hint);
        let text = buffer_text(&buf, area);
        assert!(text.contains("Sign in to Fuigo"), "header: {text:?}");
        assert!(text.contains("accounts.x.ai/device"), "url: {text:?}");
        assert!(text.contains("ABCD-EFGH"), "device code: {text:?}");
        assert!(
            text.contains("Waiting for approval"),
            "waiting line: {text:?}"
        );
    }

    #[test]
    fn render_auth_shows_trust_question() {
        let _theme = fuigo_pager::theme::cache::pin_theme();
        let theme = Theme::current();
        let area = Rect::new(0, 0, 80, 14);
        let mut buf = Buffer::empty(area);
        let hint = MinimalAuthHint::TrustFolder {
            workspace: PathBuf::from("/home/agent/project"),
            error: None,
        };
        render_auth(&mut buf, area, &theme, &hint);
        let text = buffer_text(&buf, area);
        assert!(
            text.contains("Do you trust the contents of this directory?"),
            "question: {text:?}"
        );
        assert!(
            text.contains("/home/agent/project"),
            "workspace path: {text:?}"
        );
        assert!(text.contains("Yes, proceed"), "yes option: {text:?}");
        assert!(text.contains("No, quit"), "no option: {text:?}");
        assert!(text.contains("Enter or y to trust"), "hint line: {text:?}");
        assert!(text.contains("posing security risks"), "warning: {text:?}");
    }

    /// P167: when the last "yes" recorded nothing, the minimal trust question shows why (it paints no welcome toast).
    #[test]
    fn p167_render_auth_shows_the_trust_error_and_sizes_for_it() {
        let _theme = fuigo_pager::theme::cache::pin_theme();
        let theme = Theme::current();
        let trust = TrustState::Pending {
            workspace: PathBuf::from("/home/agent/project"),
        };
        let reason = "Couldn't save folder trust: the trust store could not be read.";
        let hint = minimal_auth_hint(&AuthState::Done, &trust, true, false, Some(reason));
        let area = Rect::new(0, 0, 80, 16);
        let mut buf = Buffer::empty(area);
        render_auth(&mut buf, area, &theme, &hint);
        let text = buffer_text(&buf, area);
        assert!(text.contains("trust store could not be read"), "error: {text:?}");
        assert!(text.contains("Yes, proceed"), "the question stays answerable: {text:?}");
        let without = MinimalAuthHint::TrustFolder {
            workspace: PathBuf::from("/home/agent/project"),
            error: None,
        };
        assert!(auth_hint_rows(&hint, 80) > auth_hint_rows(&without, 80));
    }

    #[test]
    fn auth_hint_rows_covers_trust_path_wrap() {
        let long = "x".repeat(200);
        let hint = MinimalAuthHint::TrustFolder {
            workspace: PathBuf::from(long),
            error: None,
        };
        let rows = auth_hint_rows(&hint, 40);
        // The 200-char path wraps to 5 rows at width 40, so the total sits well above the fixed rows
        assert!(rows >= 12, "expected room for wrapped path, got {rows}");
    }

    fn buffer_text(buf: &Buffer, area: Rect) -> String {
        let mut text = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                if let Some(c) = buf.cell((x, y)) {
                    text.push_str(c.symbol());
                }
            }
            text.push('\n');
        }
        text
    }
}
