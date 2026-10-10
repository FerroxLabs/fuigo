//! Invisible/spoofing-character policy for remote-influenced text embedded in model-facing lines (reminders and similar) in this crate.
//! A weaker title sanitizer exists at `session::persistence::sanitize_rename_title`.
//! A weaker tool-description sanitizer exists at `fuigo_tools::implementations::search_tool::sanitize_description`.
//! New consumers in this crate should prefer this policy.

/// Characters flattened out of remote-influenced text.
/// Covered: controls, Unicode line/paragraph separators, every format (Cf) character, variation selectors, and invisible filler letters.
/// The format class includes the tag block used for invisible-text smuggling.
/// Ranges are widened to whole blocks (fail closed on unassigned code points).
pub(crate) fn is_invisible_or_spoofing_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1345F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E007F}'
                | '\u{E0100}'..='\u{E01EF}'
        )
}

/// Flatten spoofable characters to spaces, preserving length and layout.
pub(crate) fn flatten_to_spaces(s: &str) -> String {
    s.chars()
        .map(|c| {
            if is_invisible_or_spoofing_char(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Flatten spoofable characters to spaces and trim; `None` when nothing legible remains.
pub(crate) fn flatten_spoofable(s: &str) -> Option<String> {
    let flattened = flatten_to_spaces(s);
    let trimmed = flattened.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flattens_controls_format_chars_and_fillers() {
        assert_eq!(
            flatten_spoofable("a\nb\u{202E}c\u{E0041}d\u{00AD}e\u{3164}f").as_deref(),
            Some("a b c d e f")
        );
    }

    #[test]
    fn all_spoofable_input_yields_none() {
        assert_eq!(flatten_spoofable("\u{200B}\u{00AD}\u{E0041}"), None);
        assert_eq!(flatten_spoofable(""), None);
    }

    /// The widened classes of the shared display set, as inclusive ranges
    const WIDENED: &[(char, char)] = &[
        ('\u{00AD}', '\u{00AD}'),
        ('\u{180E}', '\u{180E}'),
        ('\u{2028}', '\u{2029}'),
        ('\u{FFF9}', '\u{FFFB}'),
        ('\u{13430}', '\u{1343F}'),
        ('\u{1BCA0}', '\u{1BCA3}'),
        ('\u{1D173}', '\u{1D17A}'),
        ('\u{E0001}', '\u{E0001}'),
        ('\u{E0020}', '\u{E007F}'),
    ];

    /// The tag block is handled by `strip_loose_tags` so a valid flag survives a title
    fn is_flag_pass_class(c: char) -> bool {
        ('\u{E0020}'..='\u{E007F}').contains(&c)
    }

    /// Drift guard: this crate's policy is a superset of the shared display set over every code point
    #[test]
    fn spoofing_policy_covers_the_shared_display_set() {
        for c in '\0'..=char::MAX {
            if fuigo_tty_utils::is_unsafe_display_char(c) {
                assert!(is_invisible_or_spoofing_char(c), "U+{:04X}", c as u32);
            }
        }
    }

    /// Titles lose every widened class (they stay narrower on ZWJ and ZWNJ for emoji and Persian text)
    #[test]
    fn rename_title_sanitizer_drops_every_widened_class() {
        for &(first, last) in WIDENED {
            for c in (first..=last).filter(|c| !is_flag_pass_class(*c)) {
                assert!(
                    crate::session::persistence::is_forbidden_title_char(c),
                    "U+{:04X}",
                    c as u32
                );
            }
        }
        assert!(!crate::session::persistence::is_forbidden_title_char('\u{200D}'));
        assert!(!crate::session::persistence::is_forbidden_title_char('\u{1F3F4}'));
    }
}
