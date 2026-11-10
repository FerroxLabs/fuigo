//! Single-row welcome toast overlay (above the prompt when present).

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use unicode_width::UnicodeWidthStr;

use crate::render::SafeBuf;
use crate::theme::Theme;
use crate::views::goal_detail::truncate_to_width;

/// Greedy word wrap by display width; a word wider than `width` is broken, so no text is dropped.
pub(crate) fn wrap_toast_lines(msg: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in msg.split_whitespace() {
        let mut word = word;
        let mut ww = UnicodeWidthStr::width(word);
        loop {
            let gap = usize::from(cur_w > 0);
            if cur_w + gap + ww <= width {
                if gap == 1 {
                    cur.push(' ');
                }
                cur.push_str(word);
                cur_w += gap + ww;
                break;
            }
            if cur_w > 0 {
                lines.push(std::mem::take(&mut cur));
                cur_w = 0;
                continue;
            }
            // A single word wider than the line: break it at the width
            let mut head = String::new();
            let mut hw = 0usize;
            let mut rest_at = word.len();
            for (i, ch) in word.char_indices() {
                let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
                if hw + cw > width && !head.is_empty() {
                    rest_at = i;
                    break;
                }
                head.push(ch);
                hw += cw;
            }
            lines.push(head);
            word = &word[rest_at..];
            ww = UnicodeWidthStr::width(word);
            if word.is_empty() {
                break;
            }
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// Prefer rows just above the prompt, right-aligned to it; a message wider than the screen wraps onto more rows (up to the area) instead of being cut.
/// With no prompt (login / gate), paint up from the last row of `area`.
/// Stacked welcome layouts put the version badge there, so the toast may overlay it briefly.
pub(crate) fn paint_welcome_toast(
    buf: &mut Buffer,
    area: Rect,
    msg: &str,
    prompt_rect: Option<Rect>,
) {
    let theme = Theme::current();
    let max_msg = (area.width as usize).saturating_sub(4);
    if max_msg == 0 || area.height == 0 {
        return;
    }
    let prompt = prompt_rect.filter(|r| r.width > 0 && r.y > area.y);
    let bottom_y = match prompt {
        Some(prompt) => prompt.y.saturating_sub(1),
        None => area.bottom().saturating_sub(1),
    };
    let avail_rows = (bottom_y.saturating_sub(area.y) + 1) as usize;
    let mut lines: Vec<String> = if UnicodeWidthStr::width(msg) <= max_msg {
        vec![msg.to_string()]
    } else {
        wrap_toast_lines(msg, max_msg)
    };
    if lines.len() > avail_rows {
        lines.truncate(avail_rows);
        if let Some(last) = lines.last_mut() {
            *last = truncate_to_width(&format!("{last}\u{2026}"), max_msg);
        }
    }
    let block_w = lines
        .iter()
        .map(|l| UnicodeWidthStr::width(l.as_str()))
        .max()
        .unwrap_or(0)
        + 2;
    let w = block_w as u16;
    let x = if let Some(prompt) = prompt {
        let max_x = area.right().saturating_sub(w).max(area.x);
        prompt.right().saturating_sub(w + 1).clamp(area.x, max_x)
    } else {
        area.right().saturating_sub(w.saturating_add(1))
    };
    let style = Style::default()
        .fg(theme.accent_user)
        .bg(theme.bg_base)
        .add_modifier(Modifier::BOLD);
    let top_y = bottom_y + 1 - lines.len() as u16;
    for (i, line) in lines.iter().enumerate() {
        let pad = block_w - 2 - UnicodeWidthStr::width(line.as_str());
        let toast = format!(" {line}{} ", " ".repeat(pad));
        buf.set_string_safe(x, top_y + i as u16, &toast, style);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toast_row(buf: &Buffer, area: Rect, y: u16) -> String {
        (area.x..area.right())
            .map(|x| buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn paint_welcome_toast_truncates_narrow_width() {
        let area = Rect::new(0, 0, 40, 6);
        let prompt = Rect::new(0, 4, 40, 2);
        let mut buf = Buffer::empty(area);
        let long = crate::app::link_opener::browser_unavailable_line(
            "https://x.ai/legal/terms-of-service",
            false,
        );

        paint_welcome_toast(&mut buf, area, &long, Some(prompt));
        let rows: Vec<String> = (0..prompt.y)
            .map(|y| toast_row(&buf, area, y).trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        assert!(rows.len() > 1, "narrow width must wrap: {rows:?}");
        assert_eq!(rows.join(" "), long, "the whole message must show");
        assert!(
            rows[0].contains("https://x.ai"),
            "URL-first message should keep the URL at the start: {rows:?}"
        );
        assert!(
            !toast_row(&buf, area, prompt.y).contains("https://"),
            "truncated toast must not spill into prompt row"
        );
    }

    #[test]
    fn paint_welcome_toast_truncates_wide_glyphs_by_display_width() {
        let area = Rect::new(0, 0, 12, 4);
        let prompt = Rect::new(0, 2, 12, 2);
        let mut buf = Buffer::empty(area);
        // Each CJK glyph is display width 2; char-count truncation would overfill.
        let msg = "你好世界测试文字更多内容";
        paint_welcome_toast(&mut buf, area, msg, Some(prompt));
        let y = prompt.y.saturating_sub(1);
        let row = toast_row(&buf, area, y);
        assert!(
            row.contains('\u{2026}'),
            "wide glyphs must truncate by display width: {row:?}"
        );
        let content: String = row.chars().filter(|c| *c != ' ').collect();
        assert!(
            UnicodeWidthStr::width(content.as_str()) <= area.width as usize,
            "painted width must fit area: {row:?}"
        );
        assert!(
            !toast_row(&buf, area, prompt.y).contains('你'),
            "must not spill into prompt row"
        );
    }

    #[test]
    fn paint_welcome_toast_wraps_a_long_refusal_whole() {
        let msg = "Couldn't delete session: This session is open in another Fuigo window. Close it there, or turn on the shared leader (`--leader`) to use it from several windows.";
        let area = Rect::new(0, 0, 80, 12);
        let prompt = Rect::new(2, 9, 76, 3);
        let mut buf = Buffer::empty(area);
        paint_welcome_toast(&mut buf, area, msg, Some(prompt));
        let text: Vec<String> = (0..prompt.y)
            .map(|y| toast_row(&buf, area, y).trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        assert!(text.len() > 1, "a long message must wrap: {text:?}");
        assert_eq!(text.join(" "), msg, "the whole refusal must show");
        assert!(
            !toast_row(&buf, area, prompt.y).contains("Couldn't"),
            "must not spill into the prompt row"
        );
    }

    #[test]
    fn paint_welcome_toast_right_aligns_to_prompt() {
        let area = Rect::new(0, 0, 80, 10);
        let prompt = Rect::new(2, 8, 76, 2);
        let mut buf = Buffer::empty(area);
        let msg = "ok";
        paint_welcome_toast(&mut buf, area, msg, Some(prompt));

        let y = prompt.y.saturating_sub(1);
        let row = toast_row(&buf, area, y);
        assert!(row.contains("ok"), "toast must paint: {row:?}");
        let toast = " ok ";
        let w = UnicodeWidthStr::width(toast) as u16;
        let expected_x = prompt.right().saturating_sub(w + 1);
        let content_x = (area.x..area.right())
            .find(|&x| buf.cell((x, y)).is_some_and(|c| c.symbol() == "o"))
            .expect("expected toast content");
        assert_eq!(
            content_x,
            expected_x + 1,
            "toast should right-align to prompt (content after pad)"
        );
    }

    #[test]
    fn paint_welcome_toast_without_prompt_right_aligns_bottom_row() {
        let area = Rect::new(0, 0, 80, 5);
        let mut buf = Buffer::empty(area);
        paint_welcome_toast(&mut buf, area, "ok", None);
        let y = area.bottom().saturating_sub(1);
        let row = toast_row(&buf, area, y);
        assert!(
            row.contains("ok"),
            "toast must paint on bottom row: {row:?}"
        );
        let toast = " ok ";
        let w = UnicodeWidthStr::width(toast) as u16;
        let expected_x = area.right().saturating_sub(w.saturating_add(1));
        let content_x = (area.x..area.right())
            .find(|&x| buf.cell((x, y)).is_some_and(|c| c.symbol() == "o"))
            .expect("expected toast content");
        assert_eq!(
            content_x,
            expected_x + 1,
            "no-prompt toast should right-align within area (content after pad)"
        );
    }
}
