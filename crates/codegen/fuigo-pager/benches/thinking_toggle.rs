//! Keypress-to-frame cost of the Ctrl+E thinking toggle on a long transcript.
//!
//! Builds a ~2,000-entry scrollback with several thinking blocks and runs of tool calls, then times
//! what one Ctrl+E press costs the UI thread: `expand_all_thinking()`, the layout pass the next
//! frame performs (`prepare_layout`), and painting the visible window. Prints the median and p95 of
//! the samples (alternating expand and collapse). Run: `cargo bench -p fuigo-pager --bench thinking_toggle`.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::time::Instant;

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use fuigo_pager::appearance::cache;
use fuigo_pager::scrollback::render::render_scrolled_entries_with_scratch;
use fuigo_pager::scrollback::{RenderBlock, ScrollbackState};
use fuigo_pager::theme::Theme;

const ENTRIES: usize = 2000;
const THINK_EVERY: usize = 250;
const WIDTH: u16 = 120;
const HEIGHT: u16 = 50;
const SAMPLES: usize = 300;

fn build_state() -> ScrollbackState {
    cache::set_show_thinking_blocks(true);
    cache::set_group_tool_verbs(true);
    let mut state = ScrollbackState::new();
    let thought = "weighing the options for the next edit and checking the earlier output ".repeat(12);
    for i in 0..ENTRIES {
        if i % THINK_EVERY == 0 {
            state.push_block(RenderBlock::thinking(thought.clone()));
        } else if i % 10 == 1 {
            state.push_block(RenderBlock::user_prompt(format!("Question {i}: what does module {i} do?")));
        } else if i % 10 == 9 {
            state.push_block(RenderBlock::agent_message(format!("Answer {i}. It wires the {i}th handler.\n\n- first point about module {i}\n- second point about module {i}\n\n```rust\nfn handler_{i}() {{ run({i}); }}\n```")));
        } else {
            state.push_block(RenderBlock::read(format!("src/module_{i}.rs"), None));
        }
    }
    state.prepare_layout(WIDTH, HEIGHT);
    state
}

fn paint(state: &ScrollbackState, buf: &mut Buffer, offset: usize) {
    let viewport = Rect::new(0, 0, WIDTH, HEIGHT);
    let theme = Theme::current();
    let n = state.len();
    let layouts = state.get_cached_entry_layouts().expect("layout cache");
    let (paint_range, content_y0) = state.paint_window(0..n, offset, HEIGHT as usize);
    let window = state.entries_in_range(paint_range.clone());
    buf.reset();
    render_scrolled_entries_with_scratch(
        buf, viewport, &window, offset, None, &theme, state.appearance(),
        &layouts[paint_range.clone()], 0, None, None, None, content_y0, paint_range.start, &[], None, None,
    );
}

fn total_height(state: &ScrollbackState) -> usize {
    let n = state.len();
    let v = state.get_cached_virtual_y().expect("layout cache");
    let l = state.get_cached_entry_layouts().expect("layout cache");
    v[n - 1] + l[n - 1].height as usize + l[n - 1].gap_after as usize
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn main() {
    let mut state = build_state();
    let mut buf = Buffer::empty(Rect::new(0, 0, WIDTH, HEIGHT));
    eprintln!("transcript: {} entries, {} rows", state.len(), total_height(&state));
    let mut ms = Vec::with_capacity(SAMPLES);
    let mut rows = [0usize; 2];
    for round in 0..(SAMPLES + 10) {
        if round < 2 {
            // Warm-up, and a guard that the toggle really changes the layout (else this would time a no-op).
            state.expand_all_thinking();
            state.prepare_layout(WIDTH, HEIGHT);
            rows[round] = total_height(&state);
            continue;
        }
        if round == 2 {
            assert_ne!(rows[0], rows[1], "Ctrl+E must change the transcript height");
            eprintln!("collapsed/expanded rows: {} / {}", rows[0].min(rows[1]), rows[0].max(rows[1]));
        }
        let t = Instant::now();
        state.expand_all_thinking();
        state.prepare_layout(WIDTH, HEIGHT);
        let offset = total_height(&state).saturating_sub(HEIGHT as usize);
        paint(&state, &mut buf, offset);
        let dt = t.elapsed().as_secs_f64() * 1000.0;
        if round >= 10 {
            ms.push(dt);
        }
    }
    ms.sort_by(f64::total_cmp);
    println!(
        "thinking_toggle: n={} median={:.2} ms p95={:.2} ms max={:.2} ms",
        ms.len(), pct(&ms, 0.5), pct(&ms, 0.95), ms[ms.len() - 1]
    );
}
