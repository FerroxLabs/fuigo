//! Hero layout: the Wind mark above a plain left-aligned column of version, tagline, menu and info slot. No border, no fill.

use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Flex, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;

use crate::theme::Theme;

use super::WelcomeLayout;

/// Minimum terminal width for the hero layout (mark above a centred text column).
pub(super) const HERO_BOX_MIN_WIDTH: u16 = 60;

/// Width of the centred text column.
const COLUMN_WIDTH: u16 = 56;

/// Rows between the mark and the text column.
const MARK_GAP: u16 = 1;

/// Rows the promo upgrade CTA reserves in the info slot: a spacer row above the `[label]` button row.
/// Reserved on top of the announcement text rows so the message never paints over the button.
const UPGRADE_CTA_ROWS: u16 = 2;

const HERO_SUBTITLE: &str = "Thanks for trying Fuigo, give feedback with /feedback!";

use super::{PROMPT_HEIGHT, VERSION_GAP};

/// Rows the "thanks" subtitle occupies.
/// Hidden when the in-box info slot (changelog or announcement) is shown, to keep the box compact.
fn subtitle_rows(info_height: u16) -> u16 {
    if info_height > 0 { 0 } else { 1 }
}

/// Height of the hero box's right column: version + optional subtitle + optional info block + the gap before the menu + the menu itself.
fn right_col_height(menu_height: u16, info_height: u16) -> u16 {
    let info_gap = if info_height > 0 { 1u16 } else { 0 };
    // version(1) + subtitle + [info_gap + info] + gap-before-menu(1) + menu
    1 + subtitle_rows(info_height) + info_gap + info_height + 1 + menu_height
}

/// Minimum content-area height the hero layout needs to render the text without truncating.
/// That covers the optional error row, the text column, a one-row flex gap, and the fixed rows below (tip + prompt + version).
/// The mark is optional and never counts here: text has priority. A terminal shorter than this falls back to the stacked layout.
pub(super) fn min_content_height(
    error_height: u16,
    menu_height: u16,
    tip_height: u16,
    info_height: u16,
) -> u16 {
    min_content_height_with_prompt(
        error_height,
        menu_height,
        tip_height,
        info_height,
        PROMPT_HEIGHT,
    )
}

/// [`min_content_height`] beside a composer of `prompt_height` rows: a taller draft never reflows the
/// box, so when it no longer fits the caller falls back to the stacked layout.
pub(super) fn min_content_height_with_prompt(
    error_height: u16,
    menu_height: u16,
    tip_height: u16,
    info_height: u16,
    prompt_height: u16,
) -> u16 {
    let hero_box_height = right_col_height(menu_height, info_height);
    let gap_after_error = if error_height > 0 { 1u16 } else { 0 };
    gap_after_error
        + error_height
        + hero_box_height
        + 1
        + WelcomeLayout::fixed_below_with_prompt(tip_height, prompt_height)
}

/// Largest in-box info-slot height, at most `desired`, for which the hero box still fits in `content_height`.
/// Lets the expanded announcement grow without ever pushing the box past the fit gate.
/// The renderer trails a `…` for whatever tail still doesn't fit, so the fallback never overflows.
pub(super) fn clamp_info_height(
    desired: u16,
    content_height: u16,
    error_height: u16,
    menu_height: u16,
    tip_height: u16,
) -> u16 {
    (0..=desired)
        .rev()
        .find(|&h| content_height >= min_content_height(error_height, menu_height, tip_height, h))
        .unwrap_or(0)
}

/// Compute the hero layout: the mark slot above a borderless column with the version, tagline, info slot and menu.
///
/// Sizes the info slot here (the announcement clamped to fit, else the fixed `changelog_height`) so the renderer just draws into `hero_info`.
/// The mark gets whatever rows the text leaves, as the largest mask that fits, or none: it never takes rows from the text.
#[allow(clippy::too_many_arguments)]
pub(super) fn compute_hero_box(
    content_area: Rect,
    error_height: u16,
    menu_height: u16,
    tip_height: u16,
    changelog_height: u16,
    announcement: Option<&fuigo_announcements::RemoteAnnouncement>,
    expanded: bool,
    has_upgrade_cta: bool,
    prompt_height: u16,
) -> WelcomeLayout {
    let zero = Rect::default();
    let tip_gap = if tip_height > 0 { 1u16 } else { 0 };
    let fixed_below = WelcomeLayout::fixed_below_with_prompt(tip_height, prompt_height);

    // The column width is height-independent, so derive it once and reuse it for both the measurement and the rects
    let column_width = content_area.width.saturating_sub(4).min(COLUMN_WIDTH);
    let info_height = match announcement {
        Some(ann) => clamp_info_height(
            announcement_desired_rows(ann, column_width, expanded, has_upgrade_cta),
            content_area.height,
            error_height,
            menu_height,
            tip_height,
        ),
        None => changelog_height,
    };

    let info_gap = if info_height > 0 { 1u16 } else { 0 };
    let text_height = right_col_height(menu_height, info_height);

    let gap_after_error = if error_height > 0 { 1 } else { 0 };
    let fixed_above = gap_after_error + error_height;

    // The mark takes only the rows the text leaves, as the largest mask that fits, or none.
    // Its size and the vertical centring come from the default menu and a one-line composer, so the text column holds still while the
    // composer grows or the menu changes; a squeezed mark then shrinks upward instead of moving the text.
    let mark_block = |rows: u16| if rows > 0 { rows + MARK_GAP } else { 0 };
    let default_text = right_col_height(4, info_height);
    let default_below = WelcomeLayout::fixed_below(tip_height);
    let stable_rows = super::wind_mark::slot_rows(
        content_area.width,
        content_area
            .height
            .saturating_sub(fixed_above + default_text + 1 + default_below + MARK_GAP),
    );
    let stable_top = content_area
        .height
        .saturating_sub(fixed_above + mark_block(stable_rows) + default_text + 1 + default_below)
        / 3;
    let spare = content_area
        .height
        .saturating_sub(fixed_above + text_height + 1 + fixed_below + MARK_GAP);
    let mark_rows = super::wind_mark::slot_rows(content_area.width, spare).min(stable_rows);
    let top_pad = (stable_top + mark_block(stable_rows) - mark_block(mark_rows)).min(
        content_area
            .height
            .saturating_sub(fixed_above + mark_block(mark_rows) + text_height + 1 + fixed_below),
    );

    let [
        _,
        _,
        error,
        mark_slot,
        _,
        text_slot,
        _,
        tip,
        _,
        prompt,
        _,
        version_slot,
    ] = Layout::vertical([
        Constraint::Length(top_pad),
        Constraint::Length(gap_after_error),
        Constraint::Length(error_height),
        Constraint::Length(mark_rows),
        Constraint::Length(if mark_rows > 0 { MARK_GAP } else { 0 }),
        Constraint::Length(text_height),
        Constraint::Min(1), // flex gap
        Constraint::Length(tip_height),
        Constraint::Length(tip_gap),
        Constraint::Length(prompt_height),
        Constraint::Length(VERSION_GAP),
        Constraint::Length(1),
    ])
    .areas(content_area);

    // Horizontally center the mark slot (full width: the painter centres the mask) and the text column
    let [_, hero_box, _] = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(column_width),
        Constraint::Min(0),
    ])
    .flex(Flex::Center)
    .areas(text_slot);

    // Version line at the top of the column
    let hero_version = Rect {
        height: 1,
        ..hero_box
    };
    // Subtitle line below the version; hidden when the info slot is shown
    let hero_subtitle = if subtitle_rows(info_height) > 0 {
        Rect {
            y: hero_box.y + 1,
            height: 1,
            ..hero_box
        }
    } else {
        zero
    };
    // Info block (announcement or changelog) below the version and optional subtitle
    let info_y = hero_box.y + 1 + subtitle_rows(info_height) + info_gap;
    let hero_info = if info_height > 0 {
        Rect {
            y: info_y,
            height: info_height,
            ..hero_box
        }
    } else {
        zero
    };
    // version + subtitle + info_gap + info + gap-before-menu
    let right_header_rows = 1 + subtitle_rows(info_height) + info_gap + info_height + 1;
    // The menu sits below the header rows; shortcuts right-align inside the column
    let hero_menu = Rect {
        y: hero_box.y + right_header_rows,
        height: menu_height.min(hero_box.height.saturating_sub(right_header_rows)),
        ..hero_box
    };

    WelcomeLayout {
        error,
        menu: zero,
        changelog: zero,
        tip,
        prompt,
        version: version_slot,
        hero_mark: if mark_rows > 0 { mark_slot } else { zero },
        hero_box,
        hero_version,
        hero_subtitle,
        hero_info,
        hero_menu,
    }
}

/// Hit-test rects produced by [`render_hero_box`].
pub(super) struct HeroBoxRects {
    /// Hit-test rect per menu item row (for clicks and hover).
    pub(super) menu_rects: Vec<Rect>,
    /// Clickable changelog info block, if drawn.
    pub(super) changelog_cta_rect: Option<Rect>,
    /// Whether the announcement overflowed (the "expandable" signal).
    pub(super) announcement_truncated: bool,
    /// Full announcement block area (clickable anywhere to toggle), if shown.
    pub(super) announcement_rect: Option<Rect>,
    /// Promo upgrade CTA `[label]` button rect (a click opens it), if drawn.
    pub(super) upgrade_cta_rect: Option<Rect>,
}

/// Render the hero text column: version, subtitle, info slot and menu.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_hero_box(
    layout: &WelcomeLayout,
    buf: &mut Buffer,
    theme: &Theme,
    menu_items: &[(&str, &str)],
    selected: Option<usize>,
    mouse_pos: Option<(u16, u16)>,
    announcement: Option<&fuigo_announcements::RemoteAnnouncement>,
    announcement_expanded: bool,
    changelog_bullets: &[String],
    changelog_has_full_notes: bool,
    upgrade_cta: Option<&str>,
) -> HeroBoxRects {
    super::render_version_badge(
        layout.hero_version,
        buf,
        theme,
        None,
        0,
        None,
        super::VersionBadgeMode::HeroInline,
    );

    // Subtitle line below the version.
    if layout.hero_subtitle.height > 0 {
        let subtitle_style = Style::default().fg(theme.gray);
        buf.set_span(
            layout.hero_subtitle.x,
            layout.hero_subtitle.y,
            &Span::styled(HERO_SUBTITLE, subtitle_style),
            layout.hero_subtitle.width,
        );
    }

    // In-box info slot: the announcement takes priority over the changelog, and only one is ever shown, always in this same position
    let mut changelog_cta_rect = None;
    let mut announcement_truncated = false;
    let mut announcement_rect = None;
    let mut upgrade_cta_rect = None;
    if layout.hero_info.height > 0 {
        if let Some(ann) = announcement {
            let (text_area, truncated, cta_rect) = render_announcement_with_upgrade_cta(
                buf,
                theme,
                layout.hero_info,
                ann,
                announcement_expanded,
                mouse_pos,
                upgrade_cta,
            );
            announcement_rect = Some(text_area);
            announcement_truncated = truncated;
            upgrade_cta_rect = cta_rect;
        } else if !changelog_bullets.is_empty() {
            changelog_cta_rect = render_hero_changelog(
                buf,
                theme,
                layout.hero_info,
                changelog_bullets,
                changelog_has_full_notes,
                mouse_pos,
            );
        }
    }

    let menu_area = layout.hero_menu;

    let menu_rects = super::menu::render_menu(
        menu_area,
        buf,
        theme,
        menu_items,
        selected,
        mouse_pos,
        menu_area.width,
    );
    HeroBoxRects {
        menu_rects,
        changelog_cta_rect,
        announcement_truncated,
        announcement_rect,
        upgrade_cta_rect,
    }
}

/// Draw the announcement text and the optional upgrade CTA into `area`.
/// The CTA rows are reserved at the bottom so a long or expanded message never overpaints the button.
/// The button is placed right after the drawn text and a spacer row.
/// Shared by the hero box and the stacked layout.
/// Returns `(text_area, truncated, upgrade_cta_rect)`.
#[allow(clippy::too_many_arguments)]
pub(super) fn render_announcement_with_upgrade_cta(
    buf: &mut Buffer,
    theme: &Theme,
    area: Rect,
    ann: &fuigo_announcements::RemoteAnnouncement,
    expanded: bool,
    mouse_pos: Option<(u16, u16)>,
    upgrade_cta: Option<&str>,
) -> (Rect, bool, Option<Rect>) {
    let cta_rows = if upgrade_cta.is_some() {
        UPGRADE_CTA_ROWS
    } else {
        0
    };
    let text_area = Rect {
        height: area.height.saturating_sub(cta_rows),
        ..area
    };
    let truncated = render_announcement_block(buf, theme, text_area, ann, expanded, mouse_pos);
    let mut cta_rect = None;
    if let Some(label) = upgrade_cta {
        use unicode_width::UnicodeWidthStr;
        let text_rows =
            announcement_text_rows(ann, text_area.width, expanded).min(text_area.height);
        let cta_y = area.y + text_rows + 1;
        if cta_y < area.y + area.height {
            // Hover follows the button cells under the mouse position, like the sibling info blocks
            // The shared painter owns the styling and truncation
            let btn_w =
                UnicodeWidthStr::width(format!("[{label}]").as_str()).min(area.width as usize);
            let hovered = mouse_pos.is_some_and(|(mx, my)| {
                my == cta_y && mx >= area.x && (mx as usize) < area.x as usize + btn_w
            });
            // A pinned (non-dismissible) promo shows its dim `cta.caption`; a dismissible one stays bare
            // No permission prompt exists on the welcome screen, so no gating; the painter drops the caption whole if too narrow
            let caption = (!crate::views::announcements::is_dismissible(ann))
                .then(|| crate::views::announcements::usable_cta_caption(ann))
                .flatten();
            cta_rect = crate::views::announcements::render_cta_button(
                buf, theme, area.x, cta_y, area.width, label, caption, hovered,
            );
        }
    }
    (text_area, truncated, cta_rect)
}

/// Render the announcement (title and message) into `area`, used by both welcome layouts.
/// Collapsed wraps to 2 lines and a `…`; expanded shows what fits.
/// The block brightens while hovered, but only when it's interactive (overflowing or already expanded).
/// Returns whether the message was truncated (the "expandable" signal).
pub(super) fn render_announcement_block(
    buf: &mut Buffer,
    theme: &Theme,
    area: Rect,
    ann: &fuigo_announcements::RemoteAnnouncement,
    expanded: bool,
    mouse_pos: Option<(u16, u16)>,
) -> bool {
    let over = mouse_pos.is_some_and(|(mx, my)| area.contains(Position::new(mx, my)));
    let mut row = area.y;
    let max_w = area.width as usize;
    if let Some(title) = ann.title.as_deref() {
        let title_color = match ann.severity.as_deref() {
            Some("critical") => theme.accent_error,
            _ => theme.warning,
        };
        let title_style = Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD);
        let display = crate::render::line_utils::truncate_str(title, max_w);
        buf.set_span(area.x, row, &Span::styled(display, title_style), area.width);
        row += 1;
    }
    if let Some(msg) = ann.message.as_deref() {
        let remaining_rows = (area.y + area.height).saturating_sub(row) as usize;
        let max_lines = if expanded {
            remaining_rows
        } else {
            remaining_rows.min(2)
        };
        // Only brighten when there's something to toggle (an overflowing message or the already-expanded state)
        // A short message that fits isn't clickable, so it must not look interactive
        let interactive = expanded || wrapped_line_count(msg, area.width) as usize > max_lines;
        let hovered = over && interactive;
        let msg_style = super::hover_style(theme, hovered, Style::default().fg(theme.gray));
        // Dim `…` affordance unless hovered.
        let ell_style = super::hover_style(
            theme,
            hovered,
            Style::default()
                .fg(theme.gray_bright)
                .add_modifier(Modifier::DIM),
        );
        return render_wrapped_text(
            buf, area.x, row, area.width, msg, msg_style, ell_style, max_lines,
        );
    }
    false
}

/// Render the changelog block (header and bullets) in the info slot.
/// When `clickable` (full notes exist), the whole block opens the notes on click and brightens while hovered; returns that clickable rect.
fn render_hero_changelog(
    buf: &mut Buffer,
    theme: &Theme,
    area: Rect,
    bullets: &[String],
    clickable: bool,
    mouse_pos: Option<(u16, u16)>,
) -> Option<Rect> {
    if area.width == 0 || area.height == 0 {
        return None;
    }

    let hovered =
        clickable && mouse_pos.is_some_and(|(mx, my)| area.contains(Position::new(mx, my)));

    let header_style = super::hover_style(
        theme,
        hovered,
        Style::default()
            .fg(theme.gray_bright)
            .add_modifier(Modifier::DIM),
    );
    let title = "Changelog";
    buf.set_span(
        area.x,
        area.y,
        &Span::styled(title, header_style),
        area.width,
    );

    // Bullets start 2 rows down (header row plus a blank), matching the height budget
    let bullet_style = super::hover_style(theme, hovered, Style::default().fg(theme.gray_bright));
    let max_text_width = area.width.saturating_sub(4) as usize; // " • " prefix plus pad
    for (i, bullet) in bullets.iter().enumerate() {
        let row = area.y + 2 + i as u16;
        if row >= area.y + area.height {
            break;
        }
        let truncated = crate::render::line_utils::truncate_str(bullet, max_text_width);
        let text = format!(" \u{2022} {truncated}");
        buf.set_span(area.x, row, &Span::styled(text, bullet_style), area.width);
    }

    clickable.then_some(area)
}

/// Word-wrap `text` into lines no wider than `width` columns.
/// A single word longer than `width` becomes its own (over-wide) line; the renderer clips it.
fn wrap_lines(text: &str, width: u16) -> Vec<String> {
    use unicode_width::UnicodeWidthStr;

    let w = width as usize;
    let mut lines: Vec<String> = Vec::new();
    if w == 0 {
        return lines;
    }
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.width() + 1 + word.width() <= w {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current = word.to_string();
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Number of rows `text` occupies when word-wrapped to `width` columns.
/// Shared by the layout height pre-pass and the renderer so they can't drift.
pub(super) fn wrapped_line_count(text: &str, width: u16) -> u16 {
    wrap_lines(text, width).len() as u16
}

/// Rows the announcement TEXT wants at `width`: title and message, the message capped at 2 wrapped lines unless `expanded`.
/// Shared with the renderer so the upgrade CTA is placed right after the drawn text (the reserved rows match the drawn rows).
pub(super) fn announcement_text_rows(
    ann: &fuigo_announcements::RemoteAnnouncement,
    width: u16,
    expanded: bool,
) -> u16 {
    let title_rows = if ann.title.is_some() { 1u16 } else { 0 };
    let msg_rows = ann.message.as_deref().map_or(0, |msg| {
        let wrapped = wrapped_line_count(msg, width);
        if expanded { wrapped } else { wrapped.min(2) }
    });
    title_rows + msg_rows
}

/// Rows the announcement info slot wants at `width`.
/// That is the text rows plus, when a promo upgrade CTA is shown, the spacer row and the `[label]` button row (`UPGRADE_CTA_ROWS`).
/// Shared with the renderer (the reserved rows match the drawn rows).
pub(super) fn announcement_desired_rows(
    ann: &fuigo_announcements::RemoteAnnouncement,
    width: u16,
    expanded: bool,
    has_upgrade_cta: bool,
) -> u16 {
    announcement_text_rows(ann, width, expanded)
        + if has_upgrade_cta { UPGRADE_CTA_ROWS } else { 0 }
}

/// Word-wrap `text` into at most `max_lines` rows at (`x`, `y`).
/// Overflow ends the last row with a `…` painted in `ell_style`.
/// Returns whether the text was truncated.
#[allow(clippy::too_many_arguments)]
fn render_wrapped_text(
    buf: &mut Buffer,
    x: u16,
    y: u16,
    width: u16,
    text: &str,
    style: Style,
    ell_style: Style,
    max_lines: usize,
) -> bool {
    use unicode_width::UnicodeWidthStr;

    if max_lines == 0 || width == 0 {
        return false;
    }
    let w = width as usize;
    let lines = wrap_lines(text, width);
    let truncated = lines.len() > max_lines;
    let visible = max_lines.min(lines.len());

    for (i, line) in lines.iter().take(visible).enumerate() {
        let row = y + i as u16;
        if i + 1 == visible && truncated {
            // Hard-cut the text and append our own styled `…` (no built-in one).
            let (head, ell_x) = if line.width() < w {
                (line.as_str(), x + line.width() as u16)
            } else {
                let cut =
                    crate::render::line_utils::byte_offset_at_width(line, w.saturating_sub(1));
                (&line[..cut], x + line[..cut].width() as u16)
            };
            buf.set_span(x, row, &Span::styled(head, style), width);
            buf.set_span(ell_x, row, &Span::styled("…", ell_style), 1);
        } else {
            buf.set_span(x, row, &Span::styled(line.as_str(), style), width);
        }
    }
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    fn extract_text(buf: &Buffer, x: u16, y: u16, width: u16) -> String {
        (x..x + width)
            .map(|col| {
                buf.cell((col, y))
                    .map_or(' ', |c| c.symbol().chars().next().unwrap_or(' '))
            })
            .collect::<String>()
            .trim_end()
            .to_string()
    }

    fn theme() -> crate::theme::Theme {
        crate::theme::Theme::current()
    }

    /// A distinctive long message whose tail ("incidents") only shows when expanded.
    /// Mirrors the enterprise-policy announcement that first showed the bug.
    const LONG_MSG: &str = "Enterprise security policy is now in effect for all \
managed devices and accounts. Report security incidents";

    fn ann(title: Option<&str>, message: Option<&str>) -> fuigo_announcements::RemoteAnnouncement {
        fuigo_announcements::RemoteAnnouncement {
            title: title.map(str::to_string),
            message: message.map(str::to_string),
            ..Default::default()
        }
    }

    fn all_text(buf: &Buffer, area: Rect) -> String {
        (area.y..area.y + area.height)
            .map(|r| extract_text(buf, area.x, r, area.width))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn wrap_short_text_single_line() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 3));
        render_wrapped_text(
            &mut buf,
            0,
            0,
            40,
            "hello world",
            Style::default(),
            Style::default(),
            2,
        );
        assert_eq!(extract_text(&buf, 0, 0, 40), "hello world");
        assert_eq!(extract_text(&buf, 0, 1, 40), "");
    }

    #[test]
    fn wrap_long_text_two_lines() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 3));
        render_wrapped_text(
            &mut buf,
            0,
            0,
            20,
            "one two three four five six",
            Style::default(),
            Style::default(),
            2,
        );
        let line0 = extract_text(&buf, 0, 0, 20);
        let line1 = extract_text(&buf, 0, 1, 20);
        assert!(!line0.is_empty());
        assert!(!line1.is_empty());
        assert_eq!(extract_text(&buf, 0, 2, 20), "");
    }

    #[test]
    fn wrap_empty_text() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 2));
        render_wrapped_text(
            &mut buf,
            0,
            0,
            20,
            "",
            Style::default(),
            Style::default(),
            2,
        );
        assert_eq!(extract_text(&buf, 0, 0, 20), "");
    }

    #[test]
    fn wrap_zero_max_lines() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 2));
        render_wrapped_text(
            &mut buf,
            0,
            0,
            20,
            "hello",
            Style::default(),
            Style::default(),
            0,
        );
        assert_eq!(extract_text(&buf, 0, 0, 20), "");
    }

    #[test]
    fn wrap_respects_max_lines() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 10, 5));
        render_wrapped_text(
            &mut buf,
            0,
            0,
            10,
            "a b c d e f g h i j k l",
            Style::default(),
            Style::default(),
            1,
        );
        assert!(!extract_text(&buf, 0, 0, 10).is_empty());
        assert_eq!(extract_text(&buf, 0, 1, 10), "");
    }

    #[test]
    fn announcement_collapsed_long_shows_two_lines_and_ellipsis() {
        let area = Rect::new(0, 0, 28, 10);
        let mut buf = Buffer::empty(area);
        let a = ann(Some("Heads up"), Some(LONG_MSG));
        let truncated = render_announcement_block(&mut buf, &theme(), area, &a, false, None);
        // Title on row 0, exactly 2 wrapped message rows, then blank.
        assert_eq!(extract_text(&buf, 0, 0, area.width), "Heads up");
        assert!(!extract_text(&buf, 0, 1, area.width).is_empty());
        assert!(!extract_text(&buf, 0, 2, area.width).is_empty());
        assert_eq!(extract_text(&buf, 0, 3, area.width), "");
        // The 2nd message line ends with the `…` affordance and reports truncation
        assert!(extract_text(&buf, 0, 2, area.width).contains('…'));
        assert!(truncated);
        // The tail of the message is hidden while collapsed.
        assert!(!all_text(&buf, area).contains("incidents"));
    }

    #[test]
    fn announcement_short_no_ellipsis_no_rect() {
        let area = Rect::new(0, 0, 40, 6);
        let mut buf = Buffer::empty(area);
        let a = ann(Some("FYI"), Some("All systems normal."));
        let truncated = render_announcement_block(&mut buf, &theme(), area, &a, false, None);
        assert!(!truncated);
        assert!(!all_text(&buf, area).contains('…'));
    }

    #[test]
    fn short_announcement_does_not_brighten_on_hover() {
        // A short message that fits isn't clickable, so hovering must not brighten it (otherwise it looks interactive when it isn't)
        let area = Rect::new(0, 0, 40, 6);
        let theme = theme();
        let a = ann(Some("FYI"), Some("All systems normal."));
        let mut buf = Buffer::empty(area);
        // Mouse over the message row (row 1; the title is row 0).
        let truncated = render_announcement_block(&mut buf, &theme, area, &a, false, Some((1, 1)));
        assert!(!truncated);
        assert_eq!(
            buf.cell((0, 1)).unwrap().fg,
            theme.gray,
            "short announcement must stay dim on hover"
        );
    }

    #[test]
    fn overflowing_announcement_brightens_on_hover() {
        // A collapsible (overflowing) message is interactive, so hovering it brightens the message to the primary color
        let area = Rect::new(0, 0, 28, 10);
        let theme = theme();
        let a = ann(Some("Heads up"), Some(LONG_MSG));
        let mut buf = Buffer::empty(area);
        let truncated = render_announcement_block(&mut buf, &theme, area, &a, false, Some((1, 1)));
        assert!(truncated);
        assert_eq!(
            buf.cell((0, 1)).unwrap().fg,
            theme.text_primary,
            "overflowing announcement should brighten on hover"
        );
    }

    #[test]
    fn announcement_expanded_shows_full_message() {
        let area = Rect::new(0, 0, 28, 12);
        // Collapsed hides the tail; expanded reveals it.
        let mut collapsed = Buffer::empty(area);
        let a = ann(Some("Heads up"), Some(LONG_MSG));
        render_announcement_block(&mut collapsed, &theme(), area, &a, false, None);
        assert!(!all_text(&collapsed, area).contains("incidents"));

        let mut expanded = Buffer::empty(area);
        let truncated = render_announcement_block(&mut expanded, &theme(), area, &a, true, None);
        assert!(all_text(&expanded, area).contains("incidents"));
        // Fully shown means nothing truncated, so no `…` and no hit-rect
        assert!(!all_text(&expanded, area).contains('…'));
        assert!(!truncated);
    }

    #[test]
    fn announcement_expanded_clamped_keeps_ellipsis() {
        // Too few rows for the full message even when expanded: renders what fits, keeps the `…`, and never overflows the area
        let area = Rect::new(0, 0, 28, 4);
        let mut buf = Buffer::empty(area);
        let a = ann(Some("Heads up"), Some(LONG_MSG));
        let truncated = render_announcement_block(&mut buf, &theme(), area, &a, true, None);
        assert!(truncated);
        assert!(all_text(&buf, area).contains('…'));
        // Nothing drawn past the area's last row.
        assert_eq!(extract_text(&buf, 0, area.height, area.width), "");
    }

    /// The upgrade CTA reserves `UPGRADE_CTA_ROWS` on top of the text rows.
    /// `render_announcement_with_upgrade_cta` paints `[label]` below the message, plus the dim `cta.caption` for a pinned promo that configures one.
    /// The button stays bare for a caption-less pinned promo or a dismissible one.
    /// Returns the button rect (button only, caption excluded).
    #[test]
    fn upgrade_cta_reserves_rows_and_returns_button_rect() {
        let area = Rect::new(0, 0, 40, 8);
        let a = ann(None, Some("Grok 4.5 is here. Upgrade now."));
        let text_rows = announcement_text_rows(&a, area.width, false);
        assert_eq!(
            announcement_desired_rows(&a, area.width, false, true),
            text_rows + UPGRADE_CTA_ROWS,
            "a CTA reserves the spacer + button rows"
        );
        assert_eq!(
            announcement_desired_rows(&a, area.width, false, false),
            text_rows
        );

        // Pinned promo with a configured caption: the button with the dim caption below
        let mut pinned = ann(None, Some("Grok 4.5 is here. Upgrade now."));
        pinned.dismissible = Some(false);
        pinned.cta = Some(fuigo_announcements::AnnouncementCta {
            label: Some("Upgrade Account".into()),
            url: Some("https://x.ai/grok".into()),
            caption: Some("or use Ctrl+O".into()),
        });
        let mut buf = Buffer::empty(area);
        let (text_area, _truncated, cta_rect) = render_announcement_with_upgrade_cta(
            &mut buf,
            &theme(),
            area,
            &pinned,
            false,
            None,
            Some("Upgrade Account"),
        );
        let rect = cta_rect.expect("CTA returns a button rect");
        assert_eq!(
            text_area.height,
            area.height - UPGRADE_CTA_ROWS,
            "text area shrinks by the reserved CTA rows"
        );
        assert!(
            rect.y >= text_area.y + text_rows,
            "button sits below the text"
        );
        assert_eq!(rect.width, 17, "rect is the [Upgrade Account] button only");
        let row = extract_text(&buf, area.x, rect.y, area.width);
        assert_eq!(
            row, "[Upgrade Account] or use Ctrl+O",
            "pinned promo hero shows the configured caption; row={row:?}"
        );

        // Caption-less pinned promo: bare button (nothing hardcoded fills in).
        pinned.cta.as_mut().unwrap().caption = None;
        let mut buf = Buffer::empty(area);
        let (_ta, _t, cta_rect) = render_announcement_with_upgrade_cta(
            &mut buf,
            &theme(),
            area,
            &pinned,
            false,
            None,
            Some("Upgrade Account"),
        );
        let rect = cta_rect.expect("caption-less pinned promo still shows the button");
        let row = extract_text(&buf, area.x, rect.y, area.width);
        assert_eq!(row, "[Upgrade Account]", "absent caption stays bare");

        // Dismissible promo: bare button even with a configured caption.
        let mut dismissible = ann(None, Some("Grok 4.5 is here. Upgrade now."));
        dismissible.cta = Some(fuigo_announcements::AnnouncementCta {
            label: Some("Upgrade Account".into()),
            url: Some("https://x.ai/grok".into()),
            caption: Some("or use Ctrl+O".into()),
        });
        let mut buf = Buffer::empty(area);
        let (_ta, _t, cta_rect) = render_announcement_with_upgrade_cta(
            &mut buf,
            &theme(),
            area,
            &dismissible,
            false,
            None,
            Some("Upgrade Account"),
        );
        let rect = cta_rect.expect("dismissible promo still shows the button");
        let row = extract_text(&buf, area.x, rect.y, area.width);
        assert!(row.contains("[Upgrade Account]"), "row={row:?}");
        assert!(
            !row.contains("Ctrl+O"),
            "dismissible hero ignores the configured caption; row={row:?}"
        );

        // No CTA: no rect, full-height text area.
        let mut buf = Buffer::empty(area);
        let (text_area, _t, cta_rect) =
            render_announcement_with_upgrade_cta(&mut buf, &theme(), area, &a, false, None, None);
        assert!(cta_rect.is_none());
        assert_eq!(text_area.height, area.height);
    }
}
