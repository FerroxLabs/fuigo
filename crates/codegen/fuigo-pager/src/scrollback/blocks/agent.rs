use crate::scrollback::block::BlockContent;
use crate::scrollback::types::{AccentStyle, BlockContext, BlockOutput};

use super::markdown_content::MarkdownContent;
use super::mermaid_content::{self, MermaidContent};
use crate::appearance::AppearanceConfig;

/// Block displaying an agent message with streaming markdown support.
///
/// This block uses [`MarkdownContent`] for incremental markdown rendering with cached word-wrapping.
/// When text arrives in chunks, call `push_chunk()` to append without re-rendering everything.
///
/// When `ctx.raw` is false, renders pretty markdown (hiding syntax).
/// When `ctx.raw` is true, renders the source markdown as-is.
#[derive(Debug, Clone)]
pub struct AgentMessageBlock {
    content: MarkdownContent,
    /// Cached image references extracted from the markdown source.
    image_refs: Vec<crate::prompt_images::ScrollbackImageRef>,
    /// Cached video references extracted from the markdown source.
    video_refs: Vec<crate::prompt_images::ScrollbackVideoRef>,
    /// Detected ` ```mermaid ` diagrams and render skeleton, populated at construction/finish (never per streaming chunk) like the media refs.
    mermaid: MermaidContent,
    /// Whether the reply is complete. `[Copy]` rows under code blocks and tables appear only on a finished reply,
    /// never while it streams (the fence may still be open and its body would change under the button).
    finished: bool,
}

impl AgentMessageBlock {
    /// Create a new agent message block with complete text.
    pub fn new(text: impl Into<String>) -> Self {
        let text = text.into();
        let image_refs = crate::prompt_images::extract_image_refs(&text);
        let video_refs = crate::prompt_images::extract_video_refs(&text);
        let content = MarkdownContent::new(text);
        let mermaid = content.mermaid_content();
        Self {
            content,
            image_refs,
            video_refs,
            mermaid,
            finished: true,
        }
    }

    /// Create an empty block for streaming.
    pub fn streaming() -> Self {
        Self {
            content: MarkdownContent::streaming(),
            image_refs: Vec::new(),
            video_refs: Vec::new(),
            mermaid: MermaidContent::default(),
            finished: false,
        }
    }

    /// Push a streaming chunk of markdown text.
    pub fn push_chunk(&mut self, chunk: &str) {
        self.content.push_chunk(chunk);
    }

    /// Push a chunk without rendering immediately.
    pub fn push_chunk_deferred(&mut self, chunk: &str) {
        self.content.push_chunk_deferred(chunk);
    }

    /// Get the source markdown text.
    pub fn text(&self) -> String {
        self.content.text()
    }

    /// Whether the source markdown is empty (zero-alloc, unlike `text()`).
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Finish streaming and do a full re-render for safety.
    pub fn finish(&mut self) {
        self.content.finish();
        let text = self.content.text();
        self.image_refs = crate::prompt_images::extract_image_refs(&text);
        self.video_refs = crate::prompt_images::extract_video_refs(&text);
        // Detection runs once the render is final, after the renderer freezes, never per streaming chunk
        self.mermaid = self.content.mermaid_content();
        self.finished = true;
    }

    /// The detected Mermaid diagrams for this message (empty until finished or constructed from complete text).
    pub fn mermaid(&self) -> &MermaidContent {
        &self.mermaid
    }

    /// Set the raw mode, re-rendering if it changed.
    pub fn set_raw_mode(&mut self, raw: bool) {
        self.content.set_raw_mode(raw);
    }

    /// Access the underlying markdown content (for viewer item building).
    pub fn content(&self) -> &MarkdownContent {
        &self.content
    }

    /// Mutable access to the underlying markdown content.
    pub fn content_mut(&mut self) -> &mut MarkdownContent {
        &mut self.content
    }

    /// Get copyable text for this block.
    ///
    /// When `raw` is true, returns the raw markdown source.
    /// When `raw` is false, returns the rendered text (styles stripped).
    pub fn copy_text(&self, raw: bool) -> String {
        if raw {
            self.content.text()
        } else {
            self.content.rendered_plain_text()
        }
    }
}

impl AgentMessageBlock {
    /// Resolve the diagram display mode from the user setting without building `output()`; cheap enough to gate the per-frame affordance path.
    fn mermaid_display_mode(&self) -> mermaid_content::MermaidDisplay {
        // Minimal mode commits static text with no draw loop to paint the clickable affordance row, so suppress it there
        // The diagram art still renders; its source stays natively selectable
        // The inline-overlay force-off flag is set iff minimal
        mermaid_content::mermaid_display_static(
            crate::appearance::cache::load_render_mermaid(),
            crate::terminal::image::scrollback_inline_overlay_forced_off(),
        )
    }

    /// Build the block's output and the diagram affordance rows together.
    /// The inserted rows (in the output) and the anchored placements (their offsets) always derive from the same layout.
    ///
    /// [`output`](Self::output) and [`diagram_affordances`](Self::diagram_affordances) each call this independently.
    /// It therefore runs twice per frame for a diagram message.
    /// It is deterministic for a given `ctx`, so the two calls produce matching rows and offsets without a shared cache that could drift.
    ///
    /// Only callers that have already confirmed there are diagrams and we are not in raw mode should reach here.
    /// The common diagram-free path never pays this build.
    fn rendered_output(
        &self,
        ctx: &BlockContext,
    ) -> (BlockOutput, Vec<mermaid_content::DiagramAffordance>) {
        let mut out = self.content.output(ctx.width as usize);
        // Diagram pre-wrap ranges in document order
        // The fence count and order are width-invariant, so range index `idx` pairs with the diagram's source (`self.mermaid.source(idx)`)
        let ranges = match self.mermaid_display_mode() {
            mermaid_content::MermaidDisplay::SourceOnly => Vec::new(),
            mermaid_content::MermaidDisplay::Affordances => self.content.mermaid_block_ranges(),
        };
        let copy_rows = if self.copy_rows_active() {
            self.content.copy_row_specs()
        } else {
            Vec::new()
        };
        if ranges.is_empty() && copy_rows.is_empty() {
            return (out, Vec::new());
        }
        let affordances =
            mermaid_content::apply_affordance_rows_with_copy(&mut out, &ranges, |idx| {
                self.mermaid.source(idx).unwrap_or_default().to_string()
            }, copy_rows);
        (out, affordances)
    }

    /// Whether this message shows `[Copy]` rows under its code blocks and tables: finished, not raw, and drawn by the interactive loop.
    fn copy_rows_active(&self) -> bool {
        self.finished && !self.content.is_raw() && super::copy_rows::copy_rows_enabled()
    }

    /// Whether a finished reply has at least one block that gets a `[Copy]` row (cheap: no text is built).
    fn has_copy_rows(&self) -> bool {
        self.copy_rows_active() && self.content.copy_row_count() > 0
    }
}

impl BlockContent for AgentMessageBlock {
    fn output(&self, ctx: &BlockContext) -> BlockOutput {
        // Common path: no diagrams (or raw mode) renders plain markdown, with no affordance machinery and no extra output rebuild
        if ctx.raw || (self.mermaid.is_empty() && !self.has_copy_rows()) {
            return self.content.output(ctx.width as usize);
        }
        self.rendered_output(ctx).0
    }

    fn diagram_affordances(&self, ctx: &BlockContext) -> Vec<mermaid_content::DiagramAffordance> {
        // Affordance rows exist only under the affordance display with diagrams
        // For every other (much more common) case, return without building output()
        let diagrams = !self.mermaid.is_empty()
            && self.mermaid_display_mode() == mermaid_content::MermaidDisplay::Affordances;
        if ctx.raw || (!diagrams && !self.has_copy_rows()) {
            return Vec::new();
        }
        self.rendered_output(ctx).1
    }

    fn estimate_extra_rows(&self) -> u16 {
        // Each diagram inserts one treatment row (affordance row or fallback caption) into output() that the source-text estimate can't see
        // Count one per diagram (a safe over-estimate if a range is empty) so the off-screen estimate never under-reserves
        // Raw mode and the `off` setting add no such row
        let copy_rows = if self.copy_rows_active() {
            self.content.copy_row_count()
        } else {
            0
        };
        let diagram_rows = if self.mermaid.is_empty()
            || self.content.is_raw()
            || self.mermaid_display_mode() == mermaid_content::MermaidDisplay::SourceOnly
        {
            0
        } else {
            self.mermaid.len()
        };
        (diagram_rows + copy_rows).min(u16::MAX as usize) as u16
    }

    fn accent(&self, _ctx: &BlockContext) -> Option<AccentStyle> {
        None
    }

    fn has_vpad_for(&self, _appearance: &AppearanceConfig) -> bool {
        false
    }

    fn has_raw_mode(&self) -> bool {
        true
    }

    fn is_foldable(&self) -> bool {
        false
    }

    fn image_references(&self) -> &[crate::prompt_images::ScrollbackImageRef] {
        &self.image_refs
    }

    fn video_references(&self) -> &[crate::prompt_images::ScrollbackVideoRef] {
        &self.video_refs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appearance::{AppearanceConfig, RenderMermaid};
    use crate::scrollback::types::Selectable;

    fn ctx(width: u16, raw: bool) -> BlockContext {
        BlockContext {
            mode: crate::scrollback::DisplayMode::Expanded,
            is_running: false,
            width,
            raw,
            max_lines: None,
            appearance: AppearanceConfig::default(),
            is_selected: false,
            cwd: None,
        }
    }

    #[test]
    fn agent_markdown_body_uses_single_logical_range() {
        let block = AgentMessageBlock::new("hello world this should wrap across lines");
        let out = block.output(&ctx(10, false));
        assert!(out.lines.len() > 1);
        assert!(out.lines.iter().all(|line| line.selection_range == Some(0)));
        assert!(
            out.lines
                .iter()
                .all(|line| !matches!(line.selectable, Selectable::None))
        );
    }

    #[test]
    fn agent_copy_text_preserves_raw_semantics() {
        let block = AgentMessageBlock::new("**bold** text");
        assert_eq!(block.copy_text(true), "**bold** text");
        assert_eq!(
            block.copy_text(false),
            block.content().rendered_plain_text()
        );
    }

    #[test]
    fn mermaid_detected_at_construction() {
        let block = AgentMessageBlock::new("```mermaid\nflowchart TD\n  A --> B\n```\n");
        assert_eq!(block.mermaid().len(), 1);
        assert_eq!(block.mermaid().source(0), Some("flowchart TD\n  A --> B\n"));
    }

    #[test]
    fn mermaid_not_detected_during_streaming_until_finish() {
        let mut block = AgentMessageBlock::streaming();
        block.push_chunk("```mermaid\nflowchart TD\n");
        // Fence still open mid-stream, so no detection
        assert!(block.mermaid().is_empty());
        block.push_chunk("A --> B\n```\n");
        assert!(
            block.mermaid().is_empty(),
            "detection runs at finish(), not per chunk"
        );
        block.finish();
        assert_eq!(block.mermaid().len(), 1);
    }

    const MERMAID_MD: &str = "```mermaid\nflowchart TD\n  A --> B\n```\n";

    #[test]
    fn mermaid_treatment_row_shown_in_auto_not_off_not_raw() {
        // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
        // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
        // switch suppresses the affordance rows under us.
        let _modes = crate::theme::cache::pin_theme();
        let non_selectable = |o: &BlockOutput| {
            o.lines
                .iter()
                .filter(|l| matches!(l.selectable, Selectable::None))
                .count()
        };
        // off: plain code block, no extra row
        crate::appearance::cache::set_render_mermaid(RenderMermaid::Off);
        let off = AgentMessageBlock::new(MERMAID_MD).output(&ctx(40, false));
        assert_eq!(non_selectable(&off), 0, "off mode must not add a row");

        // auto: exactly one extra non-selectable row beneath the diagram (the affordance row)
        // The row is blank in `output()`; the draw loop paints its `◇ mermaid [Open Image] [Copy Image Path] [Copy Source]` buttons
        crate::appearance::cache::set_render_mermaid(RenderMermaid::Auto);
        let auto = AgentMessageBlock::new(MERMAID_MD).output(&ctx(40, false));
        assert_eq!(
            auto.lines.len(),
            off.lines.len() + 1,
            "auto mode adds one treatment row"
        );
        assert_eq!(non_selectable(&auto), 1);

        // raw: verbatim source, no extra row even in auto
        crate::appearance::cache::set_render_mermaid(RenderMermaid::Auto);
        let raw = AgentMessageBlock::new(MERMAID_MD).output(&ctx(40, true));
        assert_eq!(non_selectable(&raw), 0, "raw mode shows the fence verbatim");
    }

    #[test]
    fn mermaid_treatment_row_preserves_hyperlink_line_mapping() {
        // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
        // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
        // switch suppresses the affordance rows under us.
        let _modes = crate::theme::cache::pin_theme();
        // The inserted treatment row (caption or affordance) is a joiner-continuation line, so it must NOT add a logical (pre-wrap) line
        // Otherwise the hyperlink overlay walk desyncs for the paragraph after the diagram
        let md = "before\n\n```mermaid\nA-->B\n```\n\n[link](https://example.com) trailing\n";
        crate::appearance::cache::set_render_mermaid(RenderMermaid::Off);
        let off = AgentMessageBlock::new(md).output(&ctx(60, false));
        crate::appearance::cache::set_render_mermaid(RenderMermaid::Auto);
        let block = AgentMessageBlock::new(md);
        let auto = block.output(&ctx(60, false));

        let logical = |o: &BlockOutput| o.lines.iter().filter(|l| l.joiner.is_none()).count();
        assert_eq!(
            logical(&auto),
            logical(&off),
            "treatment row must not introduce a new logical line",
        );

        // The renderer's hyperlinks are pre-wrap and unchanged by the inserted row (it lives in the BlockOutput, not the renderer)
        // Walk the output's joiners to recover each row's pre-wrap index
        // The link's pre-wrap line must still map to its row; the inserted row did not shift it
        let link_line = block
            .content()
            .with_hyperlinks(|hs| hs.iter().map(|h| h.line_index).min())
            .expect("the trailing link must be detected");
        let mut prewrap = 0usize;
        let mut mapped_text = String::new();
        for (row, line) in auto.lines.iter().enumerate() {
            if row > 0 && line.joiner.is_none() {
                prewrap += 1;
            }
            if prewrap == link_line {
                mapped_text = line
                    .content
                    .spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect();
                break;
            }
        }
        assert!(
            mapped_text.contains("example.com"),
            "link pre-wrap line {link_line} must still map to the link row, got {mapped_text:?}",
        );
    }

    // -- diagram affordance rows ---------------------------------------------

    /// Inline tags in a reply (`<kbd>`, `<b>`, a stray `<tag>`) stay in their paragraph: no extra rows, no lost text.
    #[test]
    fn inline_tags_do_not_break_the_layout() {
        let _modes = crate::theme::cache::pin_theme();
        let plain = AgentMessageBlock::new("Press Ctrl and C to stop now, then <tag> end.\n\nNext paragraph");
        let tagged = AgentMessageBlock::new(
            "Press <kbd>Ctrl</kbd> and <kbd>C</kbd> to stop <b>now</b>, then <tag> end.\n\nNext paragraph",
        );
        let rows = |block: &AgentMessageBlock| -> Vec<String> {
            block
                .output(&ctx(100, false))
                .lines
                .iter()
                .map(|l| l.content.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
                .collect()
        };
        let (plain_rows, tagged_rows) = (rows(&plain), rows(&tagged));
        assert_eq!(tagged_rows.len(), plain_rows.len(), "{tagged_rows:?} vs {plain_rows:?}");
        let first = &tagged_rows[0];
        for word in ["Press", "Ctrl", "stop", "now", "end."] {
            assert!(first.contains(word), "{word} kept on the paragraph's row: {first:?}");
        }
        assert_eq!(tagged_rows.last(), plain_rows.last());
    }

    /// `[Copy]` rows under the code blocks and tables of a finished reply.
    mod copy_rows {
        use super::*;
        use crate::scrollback::block::RenderBlock;

        const FENCE: &str = "intro\n\n```rust\nfn main() {\n\tlet x = 1;\n}\n```\n\nbye\n";
        const TABLE: &str = "intro\n\n| name | note |\n|---|---|\n| a | x\\|y |\n| b | 2 |\n\nbye\n";

        fn rows(block: &AgentMessageBlock) -> Vec<mermaid_content::DiagramAffordance> {
            block.diagram_affordances(&ctx(60, false))
        }

        #[test]
        fn finished_reply_gets_a_copy_row_under_each_code_block() {
            let _modes = crate::theme::cache::pin_theme();
            let block = AgentMessageBlock::new(FENCE);
            let affs = rows(&block);
            assert_eq!(affs.len(), 1, "one code block, one copy row");
            let copy = affs[0].copy.as_ref().expect("a copy row, not a diagram row");
            assert!(copy.label.ends_with(" rust"), "labelled with the language: {:?}", copy.label);
            assert_eq!(copy.buttons.len(), 1);
            assert_eq!(copy.buttons[0].label, "[Copy]");
            assert_eq!(
                copy.buttons[0].text, "fn main() {\n\tlet x = 1;\n}\n",
                "the button copies the body verbatim, tab included"
            );
            // The reserved row is one extra, non-selectable row beneath the block body
            let out = block.output(&ctx(60, false));
            assert!(matches!(
                out.lines[affs[0].row_offset as usize].selectable,
                Selectable::None
            ));
            crate::terminal::image::set_inline_overlay_force_off(true);
            let without = block.output(&ctx(60, false)).lines.len();
            crate::terminal::image::set_inline_overlay_force_off(false);
            assert_eq!(out.lines.len(), without + 1, "exactly one reserved row");
            // And the estimate reserves it
            assert!(block.estimate_extra_rows() >= 1);
        }

        #[test]
        fn streaming_reply_has_no_copy_row_until_it_finishes() {
            let _modes = crate::theme::cache::pin_theme();
            let mut block = AgentMessageBlock::streaming();
            block.push_chunk(FENCE);
            assert!(rows(&block).is_empty(), "no copy row while streaming");
            assert_eq!(block.estimate_extra_rows(), 0);
            block.finish();
            assert_eq!(rows(&block).len(), 1, "the copy row appears once the reply is finished");
        }

        #[test]
        fn raw_mode_and_minimal_mode_have_no_copy_rows() {
            let _modes = crate::theme::cache::pin_theme();
            let block = AgentMessageBlock::new(FENCE);
            assert!(block.diagram_affordances(&ctx(60, true)).is_empty(), "raw shows source only");
            crate::terminal::image::set_inline_overlay_force_off(true);
            let minimal = rows(&block);
            let minimal_len = block.output(&ctx(60, false)).lines.len();
            crate::terminal::image::set_inline_overlay_force_off(false);
            assert!(minimal.is_empty(), "minimal never paints the row, so it reserves none");
            assert_eq!(
                block.output(&ctx(60, false)).lines.len(),
                minimal_len + 1,
                "switching back to fullscreen reserves the row again"
            );
        }

        #[test]
        fn mermaid_keeps_its_own_row_and_gets_no_copy_row() {
            let _modes = crate::theme::cache::pin_theme();
            crate::appearance::cache::set_render_mermaid(RenderMermaid::On);
            let md = "```rust\nlet a = 1;\n```\n\n```mermaid\nA-->B\n```\n";
            let affs = rows(&AgentMessageBlock::new(md));
            assert_eq!(affs.len(), 2);
            assert!(affs[0].copy.is_some() && affs[0].source.is_empty());
            assert!(affs[1].copy.is_none() && affs[1].source == "A-->B\n");
            assert!(affs[0].row_offset < affs[1].row_offset);
        }

        #[test]
        fn table_copy_row_offers_markdown_and_tsv() {
            let _modes = crate::theme::cache::pin_theme();
            let affs = rows(&AgentMessageBlock::new(TABLE));
            assert_eq!(affs.len(), 1);
            let copy = affs[0].copy.as_ref().unwrap();
            let labels: Vec<&str> = copy.buttons.iter().map(|b| b.label.as_str()).collect();
            assert_eq!(labels, ["[Copy as Markdown]", "[Copy as TSV]"]);
            assert_eq!(
                copy.buttons[0].text,
                "| name | note |\n| --- | --- |\n| a | x\\|y |\n| b | 2 |"
            );
            assert_eq!(copy.buttons[1].text, "name\tnote\na\tx|y\nb\t2");
        }

        /// Copying a code block or a whole reply keeps its tabs.
        #[test]
        fn copying_a_reply_keeps_tabs() {
            let _modes = crate::theme::cache::pin_theme();
            let block = RenderBlock::AgentMessage(AgentMessageBlock::new(FENCE));
            for raw in [true, false] {
                let copied = block.copy_text(raw).expect("copyable text");
                assert!(
                    copied.contains("\tlet x = 1;"),
                    "raw={raw}: tab kept in the copied reply: {copied:?}"
                );
            }
            assert_eq!(block.code_block_texts(), ["fn main() {\n\tlet x = 1;\n}\n"]);
            // A reply streamed in pieces keeps them too
            let mut streamed = AgentMessageBlock::streaming();
            streamed.push_chunk("```\nif a {\n\tb();");
            streamed.push_chunk("\n}\n```\n");
            streamed.finish();
            assert_eq!(
                RenderBlock::AgentMessage(streamed).code_block_texts(),
                ["if a {\n\tb();\n}\n"]
            );
        }
    }

    mod affordances {
        use super::*;

        fn shown_text(out: &BlockOutput) -> String {
            out.lines
                .iter()
                .flat_map(|l| l.content.spans.iter())
                .map(|s| s.content.as_ref())
                .collect()
        }

        /// A detected diagram keeps its source code block on screen and exposes a single affordance row.
        /// The row carries the diagram source, the data every lazy `[Open]`/`[Copy path]`/`[Copy source]` button acts on.
        /// Rendering is lazy, so no path/state is tracked on the row.
        #[test]
        fn diagram_exposes_affordance_carrying_source_and_keeps_source_block() {
            // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
            // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
            // switch suppresses the affordance rows under us.
            let _modes = crate::theme::cache::pin_theme();
            crate::appearance::cache::set_render_mermaid(RenderMermaid::On);
            let block = AgentMessageBlock::new("intro\n\n```mermaid\nA-->B\n```\n\nbye\n");

            let affs = block.diagram_affordances(&ctx(60, false));
            assert_eq!(affs.len(), 1, "one diagram → one affordance row");
            assert_eq!(affs[0].source, "A-->B\n");

            // The diagram is shown as its source code block (never an image)
            // The affordance row sits at its reported (non-selectable) offset
            let out = block.output(&ctx(60, false));
            assert!(
                shown_text(&out).contains("A-->B"),
                "the source code block stays on screen",
            );
            assert!(matches!(
                out.lines[affs[0].row_offset as usize].selectable,
                Selectable::None
            ));
        }

        #[test]
        fn raw_mode_suppresses_affordances_and_shows_source() {
            // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
            // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
            // switch suppresses the affordance rows under us.
            let _modes = crate::theme::cache::pin_theme();
            crate::appearance::cache::set_render_mermaid(RenderMermaid::On);
            let block = AgentMessageBlock::new("```mermaid\nA-->B\n```\n");

            assert!(
                block.diagram_affordances(&ctx(60, true)).is_empty(),
                "raw mode suppresses affordances",
            );
            assert!(shown_text(&block.output(&ctx(60, true))).contains("A-->B"));

            // Toggling back to pretty restores the affordance row.
            assert_eq!(block.diagram_affordances(&ctx(60, false)).len(), 1);
        }

        #[test]
        fn off_setting_shows_source_with_no_affordances() {
            // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
            // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
            // switch suppresses the affordance rows under us.
            let _modes = crate::theme::cache::pin_theme();
            crate::appearance::cache::set_render_mermaid(RenderMermaid::Off);
            let block = AgentMessageBlock::new("```mermaid\nA-->B\n```\n");
            assert!(block.diagram_affordances(&ctx(60, false)).is_empty());
            assert!(shown_text(&block.output(&ctx(60, false))).contains("A-->B"));
        }

        #[test]
        fn copy_over_diagram_yields_fence_body() {
            // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
            // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
            // switch suppresses the affordance rows under us.
            let _modes = crate::theme::cache::pin_theme();
            use crate::scrollback::block::RenderBlock;
            crate::appearance::cache::set_render_mermaid(RenderMermaid::On);
            // Drive the real whole-block copy path (`copy_visible_text_in_state`, then `plain_text_from_output`)
            // Re-implementing the selectable filter would drift from production
            // The source code block is selectable; the blank affordance row is excluded
            let block = RenderBlock::AgentMessage(AgentMessageBlock::new(
                "```mermaid\nA-->B\nC-->D\n```\n",
            ));
            let copied = block
                .copy_visible_text_in_state(&ctx(60, false))
                .expect("the source code block yields selectable copy text");
            assert!(copied.contains("A-->B"), "copy yields source: {copied:?}");
            assert!(copied.contains("C-->D"), "copy yields source: {copied:?}");
        }

        /// With two diagrams, each affordance row anchors at its OWN (non-selectable) row in the final output, in document order.
        /// Each row carries that diagram's own source.
        #[test]
        fn two_diagrams_each_anchor_at_their_own_row() {
            // `AgentMessageBlock` reads the process-wide `INLINE_OVERLAY_FORCE_OFF`, which the mode-switch tests
            // flip (to Minimal and back) while holding the theme test lock; hold it too, or a concurrent
            // switch suppresses the affordance rows under us.
            let _modes = crate::theme::cache::pin_theme();
            crate::appearance::cache::set_render_mermaid(RenderMermaid::On);
            let md = "intro line\n\n```mermaid\nAAA-->BBB\n```\n\nmid line\n\n```mermaid\nCCC-->DDD\n```\n\nbye line\n";
            let block = AgentMessageBlock::new(md);
            assert_eq!(block.mermaid().len(), 2, "two diagrams");

            let out = block.output(&ctx(60, false));
            let affs = block.diagram_affordances(&ctx(60, false));
            assert_eq!(affs.len(), 2);
            assert!(
                affs[0].row_offset < affs[1].row_offset,
                "diagram order preserved: {} < {}",
                affs[0].row_offset,
                affs[1].row_offset,
            );
            assert_eq!(affs[0].source, "AAA-->BBB\n");
            assert_eq!(affs[1].source, "CCC-->DDD\n");
            for aff in &affs {
                assert!(matches!(
                    out.lines[aff.row_offset as usize].selectable,
                    Selectable::None
                ));
            }
            // Both diagrams' sources remain visible as code blocks.
            assert!(shown_text(&out).contains("AAA-->BBB"));
            assert!(shown_text(&out).contains("CCC-->DDD"));
        }
    }
}
