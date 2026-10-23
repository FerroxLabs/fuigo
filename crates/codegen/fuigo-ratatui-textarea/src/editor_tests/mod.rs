use std::ops::Range;

use unicode_segmentation::UnicodeSegmentation as _;

use super::EditDelta;

mod editing;
mod keys;
mod planning;
mod viewport;

fn delta(replaced_byte_range: Range<usize>, inserted_byte_range: Range<usize>) -> EditDelta {
    EditDelta {
        replaced_byte_range,
        inserted_byte_range,
    }
}

fn is_extended_grapheme_boundary(text: &str, byte: usize) -> bool {
    byte == text.len() || text.grapheme_indices(true).any(|(index, _)| index == byte)
}

/// 54.7: the boundary queries read only the neighbourhood of the byte, yet answer exactly as a scan from the start would,
/// for combining marks, joined emoji, flags, CRLF and Hangul.
#[test]
fn local_boundary_queries_match_a_scan_from_the_start() {
    use super::{
        ceil_grapheme_boundary, ceil_grapheme_boundary_scan, floor_grapheme_boundary, floor_grapheme_boundary_scan,
        is_grapheme_boundary, is_grapheme_boundary_scan,
    };
    let samples = [
        "plain ascii text",
        "e\u{301}a\u{300}\u{323}x",
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} family",
        "\u{1F1FA}\u{1F1F8}\u{1F1EB}\u{1F1F7}\u{1F1E9}\u{1F1EA}",
        "a\r\nb\r\n\r\nc",
        "\u{1100}\u{1161}\u{11A8}\u{AC00}\u{11A8}",
        "\u{1F44D}\u{1F3FD} thumbs \u{2764}\u{FE0F}",
        "",
    ];
    for text in samples {
        for byte in 0..=text.len() + 2 {
            assert_eq!(is_grapheme_boundary(text, byte), is_grapheme_boundary_scan(text, byte) && byte <= text.len(), "is {byte} in {text:?}");
            assert_eq!(floor_grapheme_boundary(text, byte), floor_grapheme_boundary_scan(text, byte), "floor {byte} in {text:?}");
            assert_eq!(ceil_grapheme_boundary(text, byte), ceil_grapheme_boundary_scan(text, byte), "ceil {byte} in {text:?}");
        }
    }
}
