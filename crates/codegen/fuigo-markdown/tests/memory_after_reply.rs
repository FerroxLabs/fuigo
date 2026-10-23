//! 54.7: a long reply that streamed in must not keep more memory after it finishes than the same reply rendered in one go.
//! Measured with a counting allocator (live heap bytes), so the bound is on memory, not on time.
#![allow(clippy::print_stderr)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use fuigo_markdown::{MarkdownStyle, StreamingMarkdownRenderer, Syntect};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn long_reply() -> String {
    let mut reply = String::new();
    for i in 0..400 {
        reply.push_str(&format!(
            "## Step {i}\n\nThis paragraph has **bold {i}**, `inline code`, and a [link {i}](https://example.com/{i}) so the \
             renderer has styled spans, link targets and wrapped text to keep for step number {i}.\n\n"
        ));
        if i % 7 == 0 {
            reply.push_str("```rust\n");
            for j in 0..25 {
                reply.push_str(&format!("    let value_{i}_{j} = compute({i}, {j}); // comment {j}\n"));
            }
            reply.push_str("```\n\n");
        }
        if i % 25 == 0 {
            reply.push_str("| name | value |\n|---|---|\n| a | 1 |\n| b | 2 |\n\n");
        }
        reply.push_str(&format!("- item one {i}\n- item two {i}\n\n"));
    }
    reply
}

#[test]
fn a_streamed_reply_keeps_no_more_than_a_one_shot_render_of_it() {
    let syntect = Syntect::new(include_bytes!("../assets/tokyo-night.tmTheme"));
    let reply = long_reply();

    // The syntax set loads each language lazily on first use and keeps it for the life of the process: pay that once, before measuring
    {
        let mut warm = StreamingMarkdownRenderer::new(MarkdownStyle::default(), true);
        warm.push(&reply);
        let _ = warm.finish(Some(&syntect));
    }

    let base = live();
    let mut streamed = StreamingMarkdownRenderer::new(MarkdownStyle::default(), true);
    let mut at = 0;
    while at < reply.len() {
        let mut end = (at + 48).min(reply.len());
        while !reply.is_char_boundary(end) {
            end += 1;
        }
        streamed.push_and_render(&reply[at..end], Some(&syntect));
        at = end;
    }
    let _ = streamed.finish(Some(&syntect));
    let streamed_bytes = live() - base;

    let base = live();
    let mut one_shot = StreamingMarkdownRenderer::new(MarkdownStyle::default(), true);
    one_shot.push(&reply);
    let _ = one_shot.finish(Some(&syntect));
    let one_shot_bytes = live() - base;

    eprintln!(
        "reply {} bytes; kept after finish: streamed {streamed_bytes}, one-shot {one_shot_bytes} ({:.2}x)",
        reply.len(),
        streamed_bytes as f64 / one_shot_bytes as f64
    );
    assert!(
        streamed_bytes as f64 <= one_shot_bytes as f64 * 1.10,
        "a streamed reply keeps {streamed_bytes} bytes against {one_shot_bytes} for the same reply rendered once"
    );
    drop((streamed, one_shot));
}
