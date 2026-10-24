//! The notice rows directly above the prompt, painted while the current model's ACP `meta` carries a `notice`.
//! It has no dismiss control and leaves only when the user switches to a model without a notice.
//! The text word-wraps under a hanging indent.
//! The text is untrusted config text: every row starts with a fixed `notice:` tag, the text is scrubbed to one line of at most
//! 160 characters (`ModelNotice::normalized`), and it is painted as plain styled cells (never markdown, never a link).
//! [`height`] must measure with the same wrap that [`render`] paints.

use fuigo_shell::sampling::types::{ModelNotice, ModelNoticeSeverity};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use crate::render::line_utils::truncate_str;
use crate::theme::Theme;

/// Rows a notice may take. Only a very narrow terminal needs more.
pub const MAX_ROWS: u16 = 4;

const ALERT_PREFIX: &str = "! ";
const INFO_PREFIX: &str = "i ";
/// Continuation rows start under the text, past the prefix.
const HANGING_INDENT: &str = "  ";
const LABEL_SEPARATOR: &str = " · ";
/// The fixed tag in front of the first row's text, so a notice reads as a model notice and cannot pass for a system message or a prompt.
pub(crate) const NOTICE_TAG: &str = "notice: ";

/// Scrubs a notice for painting: control and escape characters, bidi controls and line separators are removed (row breaks become
/// spaces), whitespace collapses to one line, and the text and label are capped. `None` when nothing is left.
pub fn sanitize(notice: ModelNotice) -> Option<ModelNotice> {
    fn scrub(text: &str) -> String {
        let clean = fuigo_tty_utils::scrub_unsafe_display(text, Some(' '));
        clean.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    ModelNotice {
        severity: notice.severity,
        text: scrub(&notice.text),
        label: notice.label.as_deref().map(scrub),
    }
    .normalized()
}

/// Rows the notice needs at `width`, at most [`MAX_ROWS`].
pub fn height(notice: &ModelNotice, width: u16) -> u16 {
    let rows = wrap(notice, width).len();
    u16::try_from(rows).unwrap_or(MAX_ROWS).min(MAX_ROWS)
}

pub fn render(area: Rect, buf: &mut Buffer, notice: &ModelNotice) {
    let theme = Theme::current();
    let (fg, prefix) = match notice.severity {
        ModelNoticeSeverity::Info => (theme.text_secondary, INFO_PREFIX),
        ModelNoticeSeverity::Warning => (theme.warning, ALERT_PREFIX),
        ModelNoticeSeverity::Critical => (theme.accent_error, ALERT_PREFIX),
    };
    let body = Style::default().fg(fg).bg(theme.bg_base);
    buf.set_style(area, body);

    let rows = wrap(notice, area.width);
    let is_cut = rows.len() > usize::from(area.height);
    for (y, (index, row)) in (area.y..area.bottom()).zip(rows.iter().enumerate()) {
        let lead = if index == 0 { prefix } else { HANGING_INDENT };
        // The last row that fits carries the rest of the text, cut with an ellipsis
        let row = if is_cut && y + 1 == area.bottom() {
            let rest = rows.get(index..).unwrap_or_default().join(" ");
            truncate_str(&rest, body_width(area.width))
        } else {
            row.clone()
        };
        let line = Line::from(vec![
            Span::styled(lead, body.add_modifier(Modifier::BOLD)),
            Span::styled(row, body),
        ]);
        buf.set_line(area.x, y, &line, area.width);
    }
}

fn body_width(width: u16) -> usize {
    usize::from(width).saturating_sub(HANGING_INDENT.len())
}

fn wrap(notice: &ModelNotice, width: u16) -> Vec<String> {
    let width = body_width(width);
    if width == 0 {
        return Vec::new();
    }
    // Scrubbed again at paint time, whatever path the notice took to get here.
    let Some(notice) = sanitize(notice.clone()) else {
        return Vec::new();
    };
    let text = match &notice.label {
        Some(label) => format!("{NOTICE_TAG}{label}{LABEL_SEPARATOR}{}", notice.text),
        None => format!("{NOTICE_TAG}{}", notice.text),
    };
    textwrap::wrap(&text, width)
        .into_iter()
        .map(std::borrow::Cow::into_owned)
        .collect()
}

#[cfg(test)]
#[path = "model_notice_banner_tests.rs"]
mod tests;
