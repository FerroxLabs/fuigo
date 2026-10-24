//! The small braille wordmark for minimal mode's committed welcome card.
//!
//! The full-screen welcome has no wordmark of its own: the Wind mark behind it (`wind_mark.rs`) is the only mark. Minimal mode prints its
//! welcome card once into scrollback, where a backdrop is not possible, so it keeps this static small logo.
//!
//! The logo is hidden entirely on legacy Windows consoles: the ConHost raster fonts do not cover the U+2800 braille block, so it renders as tofu.

use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Widget};

use crate::render::color::blend_color;
use crate::theme::Theme;

const LOGO_SMALL: &str = include_str!("../../../assets/logo/logo05.txt");

/// The braille art has no ASCII stand-in; see the module doc.
fn logo_hidden() -> bool {
    crate::glyphs::is_legacy_windows_console()
}

fn non_empty_lines(logo: &str) -> impl Iterator<Item = &str> {
    logo.lines().filter(|l| !l.is_empty())
}

fn count_lines(logo: &str) -> u16 {
    non_empty_lines(logo).count() as u16
}

/// Line count of the small logo used in minimal's committed welcome card (0 on a legacy Windows console, where the braille art is suppressed).
pub fn compact_logo_line_count() -> u16 {
    if logo_hidden() {
        0
    } else {
        count_lines(LOGO_SMALL)
    }
}

/// Render the small braille logo (centered, static) into `area` for minimal's welcome card.
/// The colour is the accent pulled back toward the canvas so it sits at roughly three-quarter strength.
/// No-op when the logo is hidden.
pub fn render_compact_logo(area: Rect, buf: &mut Buffer, theme: &Theme) {
    if logo_hidden() {
        return;
    }
    let color = blend_color(theme.bg_base, theme.accent_user, 0.78).unwrap_or(theme.accent_user);
    let lines: Vec<Line> = non_empty_lines(LOGO_SMALL)
        .map(|l| {
            Line::from(Span::styled(l.to_string(), Style::default().fg(color)))
                .alignment(Alignment::Center)
        })
        .collect();
    Paragraph::new(lines).render(area, buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_logo_line_count_matches_small_logo_when_visible() {
        if !logo_hidden() {
            assert_eq!(compact_logo_line_count(), count_lines(LOGO_SMALL));
            assert!(compact_logo_line_count() > 0);
        } else {
            assert_eq!(compact_logo_line_count(), 0);
        }
    }

    #[test]
    fn compact_logo_is_static() {
        let theme = Theme::default();
        let area = Rect::new(0, 0, 60, 6);
        let (mut a, mut b) = (Buffer::empty(area), Buffer::empty(area));
        render_compact_logo(area, &mut a, &theme);
        std::thread::sleep(std::time::Duration::from_millis(120));
        render_compact_logo(area, &mut b, &theme);
        assert_eq!(a, b);
    }
}
