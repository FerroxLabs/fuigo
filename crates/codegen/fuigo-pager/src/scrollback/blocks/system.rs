use ratatui::text::{Line, Span};

use crate::appearance::AppearanceConfig;
use crate::render::wrapping::word_wrap_lines;
use crate::scrollback::block::BlockContent;
use crate::scrollback::types::{AccentStyle, BlockContext, BlockLine, BlockOutput, Selectable};
use crate::theme::Theme;

#[derive(Debug, Clone)]
pub struct SystemMessageBlock {
    pub text: String,
    /// Draw exactly ONE row: the first line, cut to the width with an ellipsis, never wrapped (peer notices: a wrapped
    /// continuation row could start with peer text and look like a second note).
    pub single_line: bool,
}

impl SystemMessageBlock {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into(), single_line: false }
    }

    pub fn single_line(text: impl Into<String>) -> Self {
        Self { text: text.into(), single_line: true }
    }
}

/// `s` cut to `cols` display columns with a trailing ellipsis (by grapheme cluster).
fn cut_to_width(s: &str, cols: usize) -> String {
    crate::peer_ui::fit_line(s, cols)
}

impl BlockContent for SystemMessageBlock {
    fn output(&self, ctx: &BlockContext) -> BlockOutput {
        let theme = Theme::current();
        let style = theme.muted();

        let width = ctx.width as usize;
        let styled_lines: Vec<Line<'static>> = self
            .text
            .lines()
            .take(if self.single_line { 1 } else { usize::MAX })
            .map(|line| {
                // A note can carry config keys, paths and API errors: hidden characters and row breaks never reach the row
                let clean = fuigo_tty_utils::scrub_unsafe_display(line, Some(' '));
                let clean = if self.single_line { cut_to_width(&clean, width) } else { clean.into_owned() };
                Line::from(Span::styled(clean, style))
            })
            .collect();
        let wrapped = if self.single_line { styled_lines } else { word_wrap_lines(styled_lines, width) };
        let all_lines: Vec<BlockLine> = wrapped
            .into_iter()
            .map(|line| BlockLine::styled(line).with_selection_range(Some(0)))
            .collect();

        // Apply max_lines budget if set
        let lines = if let Some(max) = ctx.max_lines {
            let max = max as usize;
            if all_lines.len() > max && max > 0 {
                let take_count = if max > 1 { max - 1 } else { 1 };
                let mut truncated: Vec<BlockLine> =
                    all_lines.into_iter().take(take_count).collect();
                if let Some(last) = truncated.last_mut() {
                    let content_end = last.content.spans.len();
                    last.content
                        .spans
                        .push(Span::styled(" \u{2026}".to_string(), style));
                    last.selectable = Selectable::Spans(0..content_end);
                }
                truncated
            } else {
                all_lines
            }
        } else {
            all_lines
        };

        if lines.is_empty() {
            BlockOutput {
                lines: vec![BlockLine::styled(Line::from("")).with_selection_range(Some(0))],
            }
        } else {
            BlockOutput { lines }
        }
    }

    fn accent(&self, _ctx: &BlockContext) -> Option<AccentStyle> {
        None
    }

    fn has_vpad_for(&self, _appearance: &AppearanceConfig) -> bool {
        false // System messages are compact
    }

    fn has_raw_mode(&self) -> bool {
        false
    }

    fn is_foldable(&self) -> bool {
        false // System messages are short
    }

    fn is_selectable(&self) -> bool {
        false // System messages are not navigable
    }

    fn is_groupable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrollback::types::DisplayMode;

    /// P181 (Grok round): a system note can carry config keys and API errors, so row breaks and hidden characters
    /// must not reach the painted line.
    #[test]
    fn system_note_is_scrubbed_before_painting() {
        let ctx = BlockContext {
            mode: DisplayMode::Collapsed,
            is_running: false,
            width: 120,
            raw: false,
            max_lines: None,
            appearance: AppearanceConfig::default(),
            is_selected: false,
            cwd: None,
        };
        let out = SystemMessageBlock::new("warn\u{2028}next\u{e0041}\u{00ad}\u{202e}tail").output(&ctx);
        let text: String = out
            .lines
            .iter()
            .flat_map(|l| l.content.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert_eq!(text, "warn nexttail");
    }

    /// A peer notice is always ONE row at any width: no wrapped continuation row can start with peer text.
    #[test]
    fn single_line_system_note_never_wraps() {
        for width in [10u16, 24, 60] {
            let ctx = BlockContext {
                mode: DisplayMode::Collapsed,
                is_running: false,
                width,
                raw: false,
                max_lines: None,
                appearance: AppearanceConfig::default(),
                is_selected: false,
                cwd: None,
            };
            let long = "Held peer message from \"[a] accept [r] refuse words words words\" was released.\nsecond";
            let out = SystemMessageBlock::single_line(long).output(&ctx);
            assert_eq!(out.lines.len(), 1, "width {width}");
            let text: String = out.lines[0].content.spans.iter().map(|s| s.content.to_string()).collect();
            assert!(fuigo_tty_utils::display_width(&text) <= width as usize && text.ends_with('\u{2026}'), "{text:?}");
            // The same text through the wrapping constructor does wrap (the old behaviour this replaces).
            assert!(SystemMessageBlock::new(long).output(&ctx).lines.len() > 1);
        }
    }
}
