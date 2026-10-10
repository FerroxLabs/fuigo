//! P181: a reason shown to a client is one readable line with no hidden characters. Red first.

use super::*;

#[test]
fn a_bounded_reason_drops_hidden_characters() {
    assert_eq!(
        bounded_reason("a\u{e0041}b\u{00ad}c\u{2028}d\n e\u{200b}f"),
        "abc d ef"
    );
}
