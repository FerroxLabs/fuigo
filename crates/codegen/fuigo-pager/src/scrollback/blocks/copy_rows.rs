//! Copy affordance rows under the code blocks and tables of a finished reply.
//!
//! The rows reuse the Mermaid affordance-row machinery: a blank, non-selectable row is reserved beneath the block
//! (see [`apply_affordance_rows_with_copy`](super::mermaid_content::apply_affordance_rows_with_copy)); the draw loop paints
//! a dim label plus clickable buttons into it and registers the same mouse hit-rects the Mermaid buttons use.
//!
//! * A code block gets `⧉ <language or file name>  [Copy]`. The button copies the fence body verbatim, tabs included.
//! * A table gets `⧉ table  [Copy as Markdown]  [Copy as TSV]`. TSV pastes into a spreadsheet as cells.
//!
//! This module holds the pure parts (labels, table export, row specs) so they are unit-testable without a terminal.

use std::ops::Range;

use fuigo_markdown::{CodeBlockSpan, TableCopyMeta};

use super::mermaid_content::{CopyButton, CopyRow, MERMAID_INFO};

/// Longest label (in chars) shown for a code block's language or file name before it is cut with an ellipsis.
const MAX_LABEL_CHARS: usize = 32;

/// Label for a code block's copy row: the file name when the fence names one, else the language, else `text`.
///
/// Recognised file-name forms: an attribute (`title="a.rs"`, `file=a.rs`, `filename=a.rs`, `path=a.rs`), a
/// `lang:path` first word, or a later word that looks like a path (contains `.` or `/`).
pub(crate) fn code_block_label(info: &str) -> String {
    let info = info.trim();
    let mut words = info.split_whitespace();
    let first = words.next().unwrap_or("");
    let rest: Vec<&str> = words.collect();

    let unquote = |s: &str| s.trim_matches(|c| c == '"' || c == '\'').to_string();
    let attr = |word: &str| -> Option<String> {
        let (key, value) = word.split_once('=')?;
        let key = key.trim_start_matches('{');
        matches!(key, "title" | "file" | "filename" | "path")
            .then(|| unquote(value.trim_end_matches('}')))
            .filter(|v| !v.is_empty())
    };
    let looks_like_path = |word: &str| !word.contains('=') && (word.contains('.') || word.contains('/'));

    let file = std::iter::once(first)
        .chain(rest.iter().copied())
        .find_map(attr)
        .or_else(|| {
            first
                .split_once(':')
                .map(|(_, path)| path)
                .filter(|path| looks_like_path(path))
                .map(str::to_string)
        })
        .or_else(|| rest.iter().copied().find(|w| looks_like_path(w)).map(unquote));

    let lang = first
        .split(':')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}' || c == '.');
    let label = match (file, lang) {
        (Some(file), _) => file,
        (None, lang) if !lang.is_empty() && !lang.contains('=') => lang.to_string(),
        _ => "text".to_string(),
    };
    truncate_label(&label)
}

fn truncate_label(label: &str) -> String {
    if label.chars().count() <= MAX_LABEL_CHARS {
        return label.to_string();
    }
    let cut: String = label.chars().take(MAX_LABEL_CHARS - 1).collect();
    format!("{cut}\u{2026}")
}

/// A table's rows of cell text (header first), or `None` when the cell grid does not match its column count.
fn table_grid(meta: &TableCopyMeta) -> Option<Vec<Vec<String>>> {
    if meta.n_cols == 0 || meta.cells.is_empty() || !meta.cells.len().is_multiple_of(meta.n_cols) {
        return None;
    }
    Some(
        meta.cells
            .chunks(meta.n_cols)
            .map(|row| {
                row.iter()
                    .map(|cell| cell.text.replace(['\n', '\r'], " "))
                    .collect()
            })
            .collect(),
    )
}

/// The table as tab-separated values: cells joined by tabs, rows by newlines.
/// Tabs inside a cell become spaces so the shape survives pasting into a spreadsheet.
pub(crate) fn table_tsv(meta: &TableCopyMeta) -> Option<String> {
    let grid = table_grid(meta)?;
    Some(
        grid.iter()
            .map(|row| {
                row.iter()
                    .map(|cell| cell.replace('\t', " "))
                    .collect::<Vec<_>>()
                    .join("\t")
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// The table as a GitHub-style Markdown table: a header row, a `---` separator row, then the body rows.
/// A literal `|` inside a cell is escaped so it does not split the cell.
pub(crate) fn table_markdown(meta: &TableCopyMeta) -> Option<String> {
    let grid = table_grid(meta)?;
    let line = |row: &[String]| {
        let cells: Vec<String> = row.iter().map(|c| c.replace('|', "\\|")).collect();
        format!("| {} |", cells.join(" | "))
    };
    let mut out = Vec::with_capacity(grid.len() + 1);
    out.push(line(&grid[0]));
    out.push(format!("|{}", " --- |".repeat(meta.n_cols)));
    out.extend(grid[1..].iter().map(|row| line(row)));
    Some(out.join("\n"))
}

fn is_mermaid(info: &str) -> bool {
    info.split_whitespace()
        .next()
        .is_some_and(|w| w.eq_ignore_ascii_case(MERMAID_INFO))
}

/// Whether a fence gets a copy row: it has a body to copy and is not a Mermaid diagram (which has its own affordance row).
fn code_block_copyable(span: &CodeBlockSpan) -> bool {
    !span.output_line_range.is_empty() && !span.body.is_empty() && !is_mermaid(&span.info)
}

/// Number of copy rows the given blocks produce (what [`copy_row_specs`] would return, without building the text).
pub(crate) fn copy_row_count(code_blocks: &[CodeBlockSpan], tables: &[TableCopyMeta]) -> usize {
    code_blocks.iter().filter(|b| code_block_copyable(b)).count()
        + tables
            .iter()
            .filter(|t| t.line_count > 0 && table_grid(t).is_some())
            .count()
}

/// The copy rows for a finished reply: `(pre-wrap line range the row follows, row)` in document order.
/// `bodies` holds each code block's text as written (parallel to `code_blocks`), so a copy keeps its tabs.
pub(crate) fn copy_row_specs(
    code_blocks: &[CodeBlockSpan],
    bodies: &[String],
    tables: &[TableCopyMeta],
) -> Vec<(Range<usize>, CopyRow)> {
    let icon = crate::glyphs::copy_icon();
    let mut specs: Vec<(Range<usize>, CopyRow)> = Vec::new();
    for (block, body) in code_blocks
        .iter()
        .zip(bodies)
        .filter(|(b, _)| code_block_copyable(b))
    {
        specs.push((
            block.output_line_range.clone(),
            CopyRow {
                label: format!("{icon} {}", code_block_label(&block.info)),
                buttons: vec![CopyButton {
                    label: "[Copy]".to_string(),
                    text: body.clone(),
                }],
            },
        ));
    }
    for table in tables.iter().filter(|t| t.line_count > 0) {
        let (Some(markdown), Some(tsv)) = (table_markdown(table), table_tsv(table)) else {
            continue;
        };
        specs.push((
            table.line_index..table.line_index + table.line_count,
            CopyRow {
                label: format!("{icon} table"),
                buttons: vec![
                    CopyButton {
                        label: "[Copy as Markdown]".to_string(),
                        text: markdown,
                    },
                    CopyButton {
                        label: "[Copy as TSV]".to_string(),
                        text: tsv,
                    },
                ],
            },
        ));
    }
    specs.sort_by_key(|(range, _)| range.end);
    specs
}

/// Copy rows exist only where the draw loop can paint and click them.
/// Minimal mode commits static text and never runs that loop, so it gets none.
pub(crate) fn copy_rows_enabled() -> bool {
    !crate::terminal::image::scrollback_inline_overlay_forced_off()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fuigo_markdown::TableCellCopy;

    fn table(n_cols: usize, cells: &[&str]) -> TableCopyMeta {
        TableCopyMeta {
            line_index: 4,
            line_count: 5,
            n_cols,
            cells: cells
                .iter()
                .map(|t| TableCellCopy {
                    text: (*t).to_string(),
                    joins: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn label_prefers_file_name_then_language() {
        assert_eq!(code_block_label("rust"), "rust");
        assert_eq!(code_block_label(""), "text");
        assert_eq!(code_block_label("rust src/main.rs"), "src/main.rs");
        assert_eq!(code_block_label("rust:src/lib.rs"), "src/lib.rs");
        assert_eq!(code_block_label("python title=\"app.py\""), "app.py");
        assert_eq!(code_block_label("ts file=index.ts"), "index.ts");
        assert_eq!(code_block_label("{.js}"), "js");
        assert_eq!(code_block_label("title=x.rs"), "x.rs");
        let long = "a".repeat(80);
        assert_eq!(code_block_label(&format!("rust {long}.rs")).chars().count(), MAX_LABEL_CHARS);
    }

    #[test]
    fn table_exports_markdown_and_tsv() {
        let t = table(2, &["name", "note", "a|b", "x\ty", "c", "two\nlines"]);
        assert_eq!(
            table_tsv(&t).unwrap(),
            "name\tnote\na|b\tx y\nc\ttwo lines"
        );
        assert_eq!(
            table_markdown(&t).unwrap(),
            "| name | note |\n| --- | --- |\n| a\\|b | x\ty |\n| c | two lines |"
        );
    }

    #[test]
    fn mismatched_grid_exports_nothing() {
        assert!(table_tsv(&table(2, &["a", "b", "c"])).is_none());
        assert!(table_markdown(&table(0, &["a"])).is_none());
    }

    #[test]
    fn specs_skip_mermaid_and_empty_blocks_and_keep_tabs() {
        let span = |info: &str, body: &str, range: Range<usize>| CodeBlockSpan {
            info: info.to_string(),
            body: body.to_string(),
            output_line_range: range,
            source_byte_range: 0..0,
        };
        let blocks = vec![
            span("rust", "fn main() {\n\tlet x = 1;\n}\n", 0..3),
            span("mermaid", "A-->B\n", 5..6),
            span("Mermaid theme=base", "A-->B\n", 7..8),
            span("txt", "", 9..9),
        ];
        let bodies: Vec<String> = blocks
            .iter()
            .map(|b| b.body.replace("    ", "\t"))
            .collect();
        let specs = copy_row_specs(&blocks, &bodies, &[table(1, &["h", "c"])]);
        assert_eq!(copy_row_count(&blocks, &[table(1, &["h", "c"])]), 2);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].0, 0..3);
        assert_eq!(specs[0].1.buttons[0].label, "[Copy]");
        assert_eq!(specs[0].1.buttons[0].text, "fn main() {\n\tlet x = 1;\n}\n");
        assert!(specs[0].1.label.ends_with(" rust"));
        assert_eq!(specs[1].0, 4..9);
        let labels: Vec<&str> = specs[1].1.buttons.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels, ["[Copy as Markdown]", "[Copy as TSV]"]);
    }
}
