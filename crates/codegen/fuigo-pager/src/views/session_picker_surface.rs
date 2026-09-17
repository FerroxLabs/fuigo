/// Which surface a picker fetch was issued for.
/// Results route back to the requesting host's storage only; a live picker on another host never absorbs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPickerHost {
    /// Welcome-screen picker (`session_picker_*` fields on `AppView`).
    Welcome,
    /// `/resume` modal on the active agent (`ActiveModal::SessionPicker`).
    AgentModal,
    /// Dashboard picker (`AppView::dashboard_session_picker`).
    Dashboard,
}

/// State for one session-picker incarnation.
/// Host-agnostic: everything a picker accumulates between open and dismiss, nothing about how a host renders it or maps its keys.
#[derive(Debug)]
pub struct SessionPickerSurface {
    /// Incarnation identity; results apply only when it matches.
    pub generation: u64,
    pub state: crate::views::picker::PickerState,
    pub entries: Option<Vec<crate::app::app_view::SessionPickerEntry>>,
    pub loading: bool,
    pub lanes: crate::views::session_picker::SessionPickerLanes,
    pub content_results: Option<Vec<fuigo_shell::extensions::session_search::SearchSessionHit>>,
    pub content_loading: bool,
    /// Per-surface counters; the dashboard host does not share the welcome picker's `session_picker_list_seq` / `session_picker_deep_search_seq`.
    pub list_seq: u64,
    pub deep_search_seq: u64,
    /// Invalidates in-flight card-detail reads when this surface's rows or filters change.
    pub detail_seq: u64,
    pub entries_query: Option<String>,
    pub source_filter: crate::views::session_picker::SourceFilter,
    pub pending_delete: Option<crate::views::session_picker::PendingDelete>,
}

impl SessionPickerSurface {
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            state: crate::views::picker::PickerState::default(),
            entries: None,
            loading: false,
            lanes: Default::default(),
            content_results: None,
            content_loading: false,
            list_seq: 0,
            deep_search_seq: 0,
            detail_seq: 0,
            entries_query: None,
            source_filter: Default::default(),
            pending_delete: None,
        }
    }
}

/// Label painted in front of a session picker's query.
const SESSION_SEARCH_LABEL: &str = " search: ";

/// Paint a session picker's search bar so the active text field is unmistakable:
/// the label goes bold in the title colour while the field has focus, and an
/// idle-but-non-empty query is dimmed (no caret) so the list, not the search
/// box, reads as the focused surface.
pub(crate) fn render_session_picker_search_bar(
    buf: &mut ratatui::buffer::Buffer,
    area: ratatui::layout::Rect,
    theme: &crate::theme::Theme,
    state: &crate::views::picker::PickerState,
) {
    crate::views::picker::render_picker_search_bar_with_label(
        buf,
        area.x,
        area.y,
        area.width,
        theme,
        SESSION_SEARCH_LABEL,
        state,
        state.search_active,
        true,
        Some(theme.bg_base),
    );
    let label_w = u16::try_from(SESSION_SEARCH_LABEL.len()).unwrap_or(0);
    if state.search_active {
        let width = label_w.min(area.width);
        if width > 0 {
            buf.set_style(
                ratatui::layout::Rect::new(area.x, area.y, width, 1),
                ratatui::style::Style::default()
                    .fg(theme.text_primary)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            );
        }
    } else if !state.query().is_empty() {
        let start = area.x.saturating_add(label_w);
        let width = area.x.saturating_add(area.width).saturating_sub(start);
        if width > 0 {
            buf.set_style(
                ratatui::layout::Rect::new(start, area.y, width, 1),
                theme.dim(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::Modifier;

    use super::{SESSION_SEARCH_LABEL, render_session_picker_search_bar};
    use crate::theme::Theme;

    fn row_text(buf: &Buffer) -> String {
        (0..buf.area.width).fold(String::new(), |mut text, x| {
            if let Some(cell) = buf.cell((x, 0)) {
                text.push_str(cell.symbol());
            }
            text
        })
    }

    #[test]
    fn inactive_nonempty_query_is_dim_without_a_caret() {
        let _theme = crate::theme::cache::pin_theme();
        let theme = Theme::current();
        let area = Rect::new(0, 0, 40, 1);
        let mut buf = Buffer::empty(area);
        let mut state = crate::views::picker::PickerState::default();
        state.search_active = false;
        state.set_query("alpha");
        render_session_picker_search_bar(&mut buf, area, &theme, &state);

        let text = row_text(&buf);
        assert!(
            text.contains(" search:"),
            "idle query must keep the search label, got {text:?}"
        );
        assert!(
            !text.contains(">search:"),
            "idle query must not use the editing marker, got {text:?}"
        );
        assert!(
            text.contains("alpha"),
            "idle query must keep the typed text, got {text:?}"
        );

        let label_w = u16::try_from(SESSION_SEARCH_LABEL.len()).unwrap_or(0);
        let dim = theme.dim();
        let mut saw_query = false;
        for x in label_w..buf.area.width {
            let Some(cell) = buf.cell((x, 0)) else {
                continue;
            };
            if cell.symbol().trim().is_empty() {
                continue;
            }
            saw_query = true;
            if let Some(fg) = dim.fg {
                assert_eq!(cell.fg, fg, "idle query must use theme.dim(), got {cell:?}");
            } else {
                assert!(
                    cell.modifier.contains(Modifier::DIM),
                    "terminal-native idle query must use DIM, got {cell:?}"
                );
            }
        }
        assert!(saw_query, "query glyphs missing from {text:?}");

        let caret = (0..buf.area.width)
            .any(|x| buf.cell((x, 0)).is_some_and(|cell| cell.bg == theme.text_primary));
        assert!(!caret, "idle query must not paint a caret, got {text:?}");
    }

    #[test]
    fn focused_search_label_uses_the_title_color() {
        let _theme = crate::theme::cache::pin_theme();
        let theme = Theme::current();
        let area = Rect::new(0, 0, 40, 1);
        let mut buf = Buffer::empty(area);
        let mut state = crate::views::picker::PickerState::default();
        state.search_active = true;
        render_session_picker_search_bar(&mut buf, area, &theme, &state);

        let text = row_text(&buf);
        assert!(text.contains(" search:"), "{text:?}");
        assert!(!text.contains('>'), "{text:?}");
        let labeled = (0..buf.area.width).any(|x| {
            buf.cell((x, 0)).is_some_and(|cell| {
                cell.symbol() == "s"
                    && cell.fg == theme.text_primary
                    && cell.modifier.contains(Modifier::BOLD)
            })
        });
        assert!(labeled, "focused label must match the modal title color");
    }
}
