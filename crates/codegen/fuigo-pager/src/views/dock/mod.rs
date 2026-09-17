//! Consolidated panel dock — the Figma "Exploration" panels layout: one
//! header row per non-empty section (Workflows / Subagents / Tasks / Watchers /
//! Queued) directly above the prompt, each with a live count. Sections with a
//! zero count are hidden; an all-zero dock renders nothing. The row sections
//! expand to inline rows with a right-aligned meta column; the Queued section
//! embeds the queue pane as its body.
//!
//! Experimental, gated by `FUIGO_DOCK_V2=1` ([`enabled`]). Keyboard model: the
//! dock cursor walks [`visible_items`] (headers + rows + `show N more`); Enter
//! toggles a section header, opens a row, or reveals a section's hidden rows.
//!
//! Height rules live in [`layout`]: the dock never asks for more rows than
//! [`MAX_DOCK_ROWS`] (raised only by an explicit reveal) or the 2-row floor plus
//! the queue body, every non-empty section keeps its header, and a section that
//! cannot show all of its rows ends with a `show N more` line and scrolls inside
//! the band it was granted.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

use crate::render::line_utils::truncate_line;
use crate::theme::Theme;
use crate::views::turn_status::SPINNER_DIVISOR;

mod layout;

pub use layout::{DockLayout, MaxRows, SectionSlots, desired_height, is_show_all_needed};

/// Rows the dock takes at rest. A section opened with `show N more` lifts this
/// (see [`DockCounts::max_rows`]) so its rows are all reachable.
pub const MAX_DOCK_ROWS: u16 = 8;

const HEADER_INDENT: &str = " ";
/// Same gutter as the header chevron, so a one-item section is not nested.
const ROW_INDENT: &str = " ";
const MORE_INDENT: &str = "   ";
/// Lines the queue body's `#N` markers up with the column its header's title
/// starts in. The header spends three columns on its chevron and the queue pane
/// already insets its own content by two, so the dock adds the last one.
const QUEUE_BODY_INDENT: u16 = 1;
const STOP_LABEL: &str = "[stop]";

/// Fuigo keeps the dock behind an env gate rather than upstream's remote
/// `dock_enabled` feature flag: it is an off-by-default experiment here.
pub fn enabled() -> bool {
    std::env::var_os("FUIGO_DOCK_V2").is_some()
}

/// Terminal row-hover tint, matching the scrollback pane's blend.
fn row_hover_bg(theme: &Theme) -> Color {
    crate::render::color::blend_color(theme.bg_base, theme.bg_dark, 0.5).unwrap_or(theme.bg_hover)
}

pub struct DockRow {
    pub kind: String,
    pub description: String,
    pub activity: Option<String>,
    /// Right-aligned meta column, e.g. `fuigo-4.5 2m14s` or `every 5m (next in 2m)`.
    pub meta: String,
    pub killable: bool,
    /// Loops only paint `[↗]` when a linked child still exists to open.
    pub openable: bool,
    /// Active work (subagents, background commands, monitors) animates the
    /// leading dot spinner; scheduled loops keep a static diamond.
    pub spinning: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    Workflows,
    Subagents,
    Tasks,
    Watchers,
    Queued,
}

impl Section {
    /// Slot in the per-section values of [`SectionSlots`]; `Queued` has none.
    pub(crate) fn slot(self) -> Option<usize> {
        match self {
            Section::Workflows => Some(0),
            Section::Subagents => Some(1),
            Section::Tasks => Some(2),
            Section::Watchers => Some(3),
            Section::Queued => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Section::Workflows => "Workflows",
            Section::Subagents => "Subagents",
            Section::Tasks => "Tasks",
            Section::Watchers => "Watchers",
            Section::Queued => "Queued",
        }
    }

    /// Every killable dock row paints `[stop]`, including subagents.
    pub fn kill_label(self) -> &'static str {
        match self {
            Section::Workflows
            | Section::Subagents
            | Section::Tasks
            | Section::Watchers
            | Section::Queued => STOP_LABEL,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DockItem {
    Header(Section),
    Row(Section, usize),
    RevealRemaining(Section),
}

/// Painted kill-control geometry for one frame. Click handling snapshots this
/// rect with the row's kill identity; a later click is ignored unless the
/// cell still resolves to that same identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DockStopHit {
    pub rect: Rect,
    pub item: DockItem,
}

/// Paint, cursor, and hit-test all resolve rows from this through
/// [`DockLayout`], so they cannot drift apart.
#[derive(Default, Clone, Copy)]
pub struct DockCounts {
    pub workflows: usize,
    pub subagents: usize,
    pub tasks: usize,
    pub watchers: usize,
    pub queued: usize,
    pub workflows_expanded: bool,
    pub subagents_expanded: bool,
    pub tasks_expanded: bool,
    pub watchers_expanded: bool,
    pub workflows_show_all: bool,
    pub subagents_show_all: bool,
    pub tasks_show_all: bool,
    pub watchers_show_all: bool,
    pub queue_body_rows: u16,
    /// First row each section paints. Sections scroll inside their own band, so
    /// a scroll never moves a header.
    pub offsets: SectionSlots<usize>,
    /// Rows the dock may take. [`MAX_DOCK_ROWS`] at rest; the caller raises it
    /// for a section the user opened, bounded by the space around the dock.
    pub max_rows: MaxRows,
}

#[derive(Default)]
pub struct DockData {
    pub workflows: Vec<DockRow>,
    pub subagents: Vec<DockRow>,
    pub tasks: Vec<DockRow>,
    pub watchers: Vec<DockRow>,
    pub queued: usize,
    pub workflows_expanded: bool,
    pub subagents_expanded: bool,
    pub tasks_expanded: bool,
    pub watchers_expanded: bool,
    pub workflows_show_all: bool,
    pub subagents_show_all: bool,
    pub tasks_show_all: bool,
    pub watchers_show_all: bool,
    pub focused: bool,
    pub cursor: usize,
    /// Reserved for the caller's queue pane; the dock widget does not paint it.
    pub queue_body_rows: u16,
    /// See [`DockCounts::offsets`].
    pub offsets: SectionSlots<usize>,
    /// See [`DockCounts::max_rows`].
    pub max_rows: MaxRows,
    pub hovered: Option<DockItem>,
    /// True when the pointer sits on the action row's kill control. The
    /// `[stop]`/`[x]` label then paints red on direct hover only and stays gray
    /// at rest, matching the Tasks pane.
    pub stop_hovered: bool,
    /// Drives the leading dot-spinner frame on active rows. Sourced from the
    /// Tasks-pane animation tick so the dock animates in lockstep with it.
    pub spinner_tick: u64,
}

impl DockData {
    pub fn counts(&self) -> DockCounts {
        DockCounts {
            workflows: self.workflows.len(),
            subagents: self.subagents.len(),
            tasks: self.tasks.len(),
            watchers: self.watchers.len(),
            queued: self.queued,
            workflows_expanded: self.workflows_expanded,
            subagents_expanded: self.subagents_expanded,
            tasks_expanded: self.tasks_expanded,
            watchers_expanded: self.watchers_expanded,
            workflows_show_all: self.workflows_show_all,
            subagents_show_all: self.subagents_show_all,
            tasks_show_all: self.tasks_show_all,
            watchers_show_all: self.watchers_show_all,
            queue_body_rows: self.queue_body_rows,
            offsets: self.offsets,
            max_rows: self.max_rows,
        }
    }

    fn rows(&self, section: Section) -> &[DockRow] {
        match section {
            Section::Workflows => &self.workflows,
            Section::Subagents => &self.subagents,
            Section::Tasks => &self.tasks,
            Section::Watchers => &self.watchers,
            Section::Queued => &[],
        }
    }
}

pub fn items(counts: &DockCounts) -> Vec<DockItem> {
    DockLayout::new(counts).rows().to_vec()
}

pub fn visible_items(data: &DockData) -> Vec<DockItem> {
    items(&data.counts())
}

/// Clips with the dock so headers never hit-test as `Queue`.
pub fn queue_body_rect(area: Rect, data: &DockData) -> Rect {
    let layout = DockLayout::with_cap(&data.counts(), area.height as usize);
    let rows = layout.rows().len() as u16;
    let height = layout
        .queue_body_rows()
        .min(area.height.saturating_sub(rows));
    if data.queued == 0 || height == 0 {
        return Rect::default();
    }
    // The queue pane paints its own `#N` markers; line them up with the header
    // title above them so the dock reads as one list.
    let indent = QUEUE_BODY_INDENT.min(area.width);
    Rect {
        x: area.x + indent,
        y: area.y + rows,
        width: area.width - indent,
        height,
    }
}

pub fn render(buf: &mut Buffer, area: Rect, theme: &Theme, data: &DockData) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let counts = data.counts();
    let layout = DockLayout::with_cap(&counts, area.height as usize);
    let bottom = area.bottom();
    let mut y = area.y;
    let action_item = action_item(data, layout.rows());
    let selected_at = |idx: usize| data.focused && idx == data.cursor;
    let highlight = |buf: &mut Buffer, y: u16, selected: bool, hovered: bool| {
        if selected {
            highlight_row(buf, area, y, theme.bg_highlight);
        } else if hovered {
            highlight_row(buf, area, y, row_hover_bg(theme));
        }
    };

    for (item_index, item) in layout.rows().iter().copied().enumerate() {
        if y >= bottom {
            return;
        }
        match item {
            DockItem::Header(section) => {
                let (count, expanded) = match section {
                    Section::Workflows => (counts.workflows, counts.workflows_expanded),
                    Section::Subagents => (counts.subagents, counts.subagents_expanded),
                    Section::Tasks => (counts.tasks, counts.tasks_expanded),
                    Section::Watchers => (counts.watchers, counts.watchers_expanded),
                    Section::Queued => (counts.queued, data.queue_body_rows > 0),
                };
                let line = section_header(theme, area.width, expanded, section.label(), count);
                buf.set_line(area.x, y, &line, area.width);
                highlight(
                    buf,
                    y,
                    selected_at(item_index),
                    data.hovered == Some(DockItem::Header(section)),
                );
            }
            DockItem::Row(section, i) => {
                let selected = selected_at(item_index);
                let hovered = data.hovered == Some(DockItem::Row(section, i));
                let show_actions = action_item == Some(DockItem::Row(section, i));
                let kill_hovered = show_actions && data.stop_hovered;
                let Some(row) = data.rows(section).get(i) else {
                    continue;
                };
                paint_row(
                    buf,
                    area,
                    y,
                    theme,
                    row,
                    show_actions,
                    kill_hovered,
                    data.spinner_tick,
                    section,
                );
                highlight(buf, y, selected, hovered);
            }
            DockItem::RevealRemaining(section) => {
                let selected = selected_at(item_index);
                // Rows the section holds but is not showing. Scrolling the band
                // changes which rows those are, never how many, so the count
                // stays put while the user moves through the section.
                let hidden = layout.hidden_rows(section);
                let arrow = crate::glyphs::disclosure_open();
                let indent_len = MORE_INDENT.len().min(area.width.saturating_sub(1) as usize);
                let line = Line::from(Span::styled(
                    format!(
                        "{}{arrow} show {hidden} more",
                        MORE_INDENT.get(..indent_len).unwrap_or(MORE_INDENT)
                    ),
                    Style::default().fg(theme.gray),
                ));
                buf.set_line(area.x, y, &line, area.width);
                highlight(
                    buf,
                    y,
                    selected,
                    data.hovered == Some(DockItem::RevealRemaining(section)),
                );
            }
        }
        y += 1;
    }
}

fn highlight_row(buf: &mut Buffer, area: Rect, y: u16, bg: ratatui::style::Color) {
    for x in area.x..area.x + area.width {
        if let Some(cell) = buf.cell_mut((x, y)) {
            cell.set_bg(bg);
        }
    }
}

fn header_chevron(expanded: bool) -> String {
    let ch = if expanded {
        crate::glyphs::disclosure_open()
    } else {
        crate::glyphs::disclosure_closed()
    };
    format!("{ch} ")
}

fn section_header(
    theme: &Theme,
    width: u16,
    expanded: bool,
    label: &str,
    count: usize,
) -> Line<'static> {
    let indent = if width > 1 { HEADER_INDENT } else { "" };
    let chevron = header_chevron(expanded);
    // Title and count only. A trailing rule made one-item sections look like a panel.
    Line::from(vec![
        Span::raw(indent),
        Span::styled(chevron, Style::default().fg(theme.gray)),
        Span::styled(
            label.to_string(),
            Style::default()
                .fg(theme.gray_bright)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {count}"), Style::default().fg(theme.gray)),
    ])
}

fn paint_row(
    buf: &mut Buffer,
    area: Rect,
    y: u16,
    theme: &Theme,
    row: &DockRow,
    show_actions: bool,
    kill_hovered: bool,
    spinner_tick: u64,
    section: Section,
) {
    let accent = Style::default().fg(theme.accent_running);
    let kill_color = if kill_hovered {
        theme.accent_error
    } else {
        theme.gray
    };
    let icon = if row.spinning {
        let frames = crate::glyphs::dot_spinner_frames();
        frames
            .get((spinner_tick / SPINNER_DIVISOR) as usize % frames.len())
            .copied()
            .unwrap_or("")
    } else {
        crate::glyphs::diamond_filled()
    };
    let mut spans = vec![
        Span::raw(ROW_INDENT),
        Span::styled(format!("{icon} "), accent),
        Span::styled(row.kind.clone(), accent),
        Span::raw(" "),
        Span::styled(
            row.description.clone(),
            Style::default().fg(theme.text_primary),
        ),
    ];
    if let Some(activity) = row.activity.as_deref().filter(|s| !s.is_empty()) {
        spans.push(Span::styled(
            format!(" — {activity}"),
            Style::default().fg(theme.gray),
        ));
    }
    let left = Line::from(spans);

    let mut meta_spans = vec![Span::styled(
        row.meta.clone(),
        Style::default().fg(theme.gray),
    )];
    if show_actions {
        if row.openable || row.killable {
            meta_spans.push(Span::raw(" "));
        }
        if row.openable {
            meta_spans.push(Span::styled(
                crate::glyphs::enlarge_button(),
                Style::default().fg(theme.gray_bright),
            ));
        }
        if row.killable {
            meta_spans.push(Span::styled(
                section.kill_label(),
                Style::default().fg(kill_color),
            ));
        }
    }
    let mut meta_line = Line::from(meta_spans);
    if meta_line.width() > area.width as usize {
        let kill = section.kill_label();
        meta_line = if show_actions && row.killable && area.width as usize >= kill.width() {
            Line::from(Span::styled(kill, Style::default().fg(kill_color)))
        } else {
            truncate_line(meta_line, area.width as usize)
        };
    }
    let meta_width = meta_line.width() as u16;
    let reserved = u16::from(meta_width > 0).saturating_add(meta_width);
    let left_budget = area.width.saturating_sub(reserved.min(area.width));
    if left_budget > 0 {
        let left = truncate_line(left, left_budget as usize);
        buf.set_line(area.x, y, &left, left_budget);
    }

    if meta_width > 0 && meta_width <= area.width {
        let x = area.x + area.width - meta_width;
        buf.set_line(x, y, &meta_line, meta_width);
    }
}

pub fn stop_button_rect(area: Rect, y: u16, section: Section) -> Option<Rect> {
    let width = section.kill_label().width() as u16;
    (area.width >= width).then(|| Rect::new(area.right() - width, y, width, 1))
}

fn action_item(data: &DockData, items: &[DockItem]) -> Option<DockItem> {
    match data.hovered.filter(|hovered| items.contains(hovered)) {
        Some(hovered) => Some(hovered),
        None if data.focused => items.get(data.cursor).copied(),
        None => None,
    }
}

pub fn hovered_stop_button_rect(area: Rect, data: &DockData) -> Option<DockStopHit> {
    let layout = DockLayout::with_cap(&data.counts(), area.height as usize);
    let item = action_item(data, layout.rows())?;
    let visible_row = layout.rows().iter().position(|it| *it == item)?;
    if visible_row >= area.height as usize {
        return None;
    }
    let DockItem::Row(section, index) = item else {
        return None;
    };
    let dock_row = data.rows(section).get(index)?;
    dock_row
        .killable
        .then(|| stop_button_rect(area, area.y + visible_row as u16, section))
        .flatten()
        .map(|rect| DockStopHit { rect, item })
}

/// Compact elapsed seconds for the dock, status line, and restore banners: `5s`, `1m05s`, and `3h14m` once an hour
/// has passed. One formatter so the surfaces cannot drift.
pub fn fmt_elapsed(secs: u64) -> String {
    crate::views::goal_detail::format_elapsed(secs.saturating_mul(1000))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
