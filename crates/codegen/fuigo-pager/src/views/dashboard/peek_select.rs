//! Drag text selection over the dashboard peek box's live tail.
//!
//! The tail is painted straight from the agent's scrollback each frame, so the selection works on the painted cells: the renderer records
//! the tail rect and a copy of its cells ([`capture_cells`]), the mouse handler tracks anchor and head in screen coordinates, and the
//! text is read back from the recorded cells ([`selected_text`]) when the button is released.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Modifier;

/// A drag selection in screen coordinates `(column, row)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeekTailSelection {
    pub anchor: (u16, u16),
    pub head: (u16, u16),
}

impl PeekTailSelection {
    /// `(start, end)` in reading order (row first, then column), both inclusive.
    fn ordered(&self) -> ((u16, u16), (u16, u16)) {
        let a = (self.anchor.1, self.anchor.0);
        let h = (self.head.1, self.head.0);
        let (lo, hi) = if a <= h { (a, h) } else { (h, a) };
        ((lo.1, lo.0), (hi.1, hi.0))
    }

    /// Whether the cell at `(col, row)` is inside the selection.
    pub fn contains(&self, col: u16, row: u16) -> bool {
        let ((c0, r0), (c1, r1)) = self.ordered();
        if row < r0 || row > r1 {
            return false;
        }
        let from = if row == r0 { c0 } else { 0 };
        let to = if row == r1 { c1 } else { u16::MAX };
        col >= from && col <= to
    }

    /// A click without a drag selects nothing.
    pub fn is_empty(&self) -> bool {
        self.anchor == self.head
    }
}

/// Clamp a screen position into `rect` so a drag past the edge keeps selecting up to the edge.
pub(crate) fn clamp_to(rect: Rect, col: u16, row: u16) -> (u16, u16) {
    let max_col = rect.x + rect.width.saturating_sub(1);
    let max_row = rect.y + rect.height.saturating_sub(1);
    (col.clamp(rect.x, max_col), row.clamp(rect.y, max_row))
}

/// The symbol of every cell in `rect`, row by row.
pub(crate) fn capture_cells(buf: &Buffer, rect: Rect) -> Vec<Vec<String>> {
    (rect.y..rect.y + rect.height)
        .map(|y| {
            (rect.x..rect.x + rect.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect()
        })
        .collect()
}

/// The selected text: each row's selected cells joined, trailing blanks trimmed, rows joined with newlines.
pub(crate) fn selected_text(cells: &[Vec<String>], rect: Rect, sel: &PeekTailSelection) -> String {
    let mut lines = Vec::new();
    for (i, row_cells) in cells.iter().enumerate() {
        let row = rect.y + i as u16;
        let line: String = row_cells
            .iter()
            .enumerate()
            .filter(|(j, _)| sel.contains(rect.x + *j as u16, row))
            .map(|(_, s)| s.as_str())
            .collect();
        lines.push(line.trim_end().to_string());
    }
    // Drop blank rows at both ends (the part of a multi-row drag that ran over padding)
    while lines.first().is_some_and(|l| l.is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// Highlight the selection by inverting its cells.
pub(crate) fn paint_selection(buf: &mut Buffer, rect: Rect, sel: &PeekTailSelection) {
    for y in rect.y..rect.y + rect.height {
        for x in rect.x..rect.x + rect.width {
            if sel.contains(x, y) {
                buf[(x, y)].modifier.insert(Modifier::REVERSED);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect() -> Rect {
        Rect::new(2, 1, 10, 3)
    }

    fn buf_with(lines: &[&str]) -> Buffer {
        let mut buf = Buffer::empty(Rect::new(0, 0, 20, 6));
        for (i, l) in lines.iter().enumerate() {
            buf.set_string(2, 1 + i as u16, l, ratatui::style::Style::default());
        }
        buf
    }

    #[test]
    fn single_row_selection_reads_back_the_dragged_cells() {
        let buf = buf_with(&["hello world", "second", "third"]);
        let cells = capture_cells(&buf, rect());
        let sel = PeekTailSelection { anchor: (2, 1), head: (6, 1) };
        assert_eq!(selected_text(&cells, rect(), &sel), "hello");
    }

    #[test]
    fn a_backwards_multi_row_drag_reads_in_reading_order() {
        let buf = buf_with(&["alpha", "beta", "gamma"]);
        let cells = capture_cells(&buf, rect());
        // Drag from the middle of row 3 back up to the middle of row 1
        let sel = PeekTailSelection { anchor: (4, 3), head: (4, 1) };
        assert_eq!(selected_text(&cells, rect(), &sel), "pha\nbeta\ngam");
    }

    #[test]
    fn a_click_without_a_drag_selects_nothing() {
        let sel = PeekTailSelection { anchor: (3, 1), head: (3, 1) };
        assert!(sel.is_empty());
    }

    #[test]
    fn clamp_keeps_a_drag_past_the_edge_inside_the_rect() {
        assert_eq!(clamp_to(rect(), 0, 0), (2, 1));
        assert_eq!(clamp_to(rect(), 99, 99), (11, 3));
        assert_eq!(clamp_to(rect(), 5, 2), (5, 2));
    }

    #[test]
    fn painting_inverts_exactly_the_selected_cells() {
        let mut buf = buf_with(&["hello world"]);
        let sel = PeekTailSelection { anchor: (2, 1), head: (4, 1) };
        paint_selection(&mut buf, rect(), &sel);
        for x in 2..=4 {
            assert!(buf[(x, 1)].modifier.contains(Modifier::REVERSED), "col {x}");
        }
        assert!(!buf[(5, 1)].modifier.contains(Modifier::REVERSED));
        assert!(!buf[(2, 2)].modifier.contains(Modifier::REVERSED));
    }
}
