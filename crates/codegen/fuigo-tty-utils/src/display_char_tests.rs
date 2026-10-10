use super::{
    escape_unsafe_display, is_unsafe_display_char, is_unsafe_title_char, replace_unsafe_display,
    cap_display_middle, display_width, scrub_log_record, scrub_model_text, scrub_terminal_text, scrub_unsafe_display, untrusted, Untrusted,
    scrub_unsafe_title, scrub_unsafe_title_with, strip_loose_tags,
};
use std::borrow::Cow;

#[test]
fn is_unsafe_display_char_covers_controls_and_bidi_format() {
    for c in ['a', ' ', '/', '\u{00e9}', '\u{05d0}', '\u{1F3F4}', '\u{FE0F}'] {
        assert!(!is_unsafe_display_char(c), "{c:?} must be safe");
    }
    for c in [
        '\u{1b}', '\n', '\t', '\u{061C}', '\u{200B}', '\u{200F}', '\u{202E}', '\u{2066}',
        '\u{2069}', '\u{206F}', '\u{FEFF}',
    ] {
        assert!(is_unsafe_display_char(c), "{:#06x} must be unsafe", c as u32);
    }
}

fn assert_class_unsafe(name: &str, first: char, last: char) {
    for c in first..=last {
        assert!(is_unsafe_display_char(c), "{name}: U+{:04X} must be unsafe", c as u32);
    }
}

#[test]
fn soft_hyphen_is_unsafe() {
    assert_class_unsafe("soft hyphen", '\u{00AD}', '\u{00AD}');
}

#[test]
fn line_and_paragraph_separators_are_unsafe() {
    assert_class_unsafe("line/paragraph separator", '\u{2028}', '\u{2029}');
}

#[test]
fn mongolian_vowel_separator_is_unsafe() {
    assert_class_unsafe("mongolian vowel separator", '\u{180E}', '\u{180E}');
}

#[test]
fn interlinear_annotation_characters_are_unsafe() {
    assert_class_unsafe("interlinear annotation", '\u{FFF9}', '\u{FFFB}');
}

#[test]
fn egyptian_hieroglyph_format_controls_are_unsafe() {
    assert_class_unsafe("hieroglyph format controls", '\u{13430}', '\u{1343F}');
}

#[test]
fn shorthand_format_controls_are_unsafe() {
    assert_class_unsafe("shorthand format controls", '\u{1BCA0}', '\u{1BCA3}');
}

#[test]
fn musical_symbol_format_controls_are_unsafe() {
    assert_class_unsafe("musical format controls", '\u{1D173}', '\u{1D17A}');
}

#[test]
fn unicode_tags_are_unsafe() {
    assert_class_unsafe("language tag", '\u{E0001}', '\u{E0001}');
    assert_class_unsafe("tag characters", '\u{E0020}', '\u{E007F}');
}

/// The edges just outside each class stay printable or are handled by their own class
#[test]
fn neighbours_of_the_widened_ranges_stay_safe() {
    for c in ['\u{00AC}', '\u{00AE}', '\u{180D}', '\u{FFF8}', '\u{FFFC}', '\u{1342F}',
        '\u{13440}', '\u{1BC9F}', '\u{1BCA4}', '\u{1D172}', '\u{1D17B}', '\u{E0002}',
        '\u{E001F}', '\u{E0080}'] {
        assert!(!is_unsafe_display_char(c), "U+{:04X} must stay safe", c as u32);
    }
}

const SCOTLAND: &str = "\u{1f3f4}\u{e0067}\u{e0062}\u{e0073}\u{e0063}\u{e0074}\u{e007f}";

#[test]
fn strip_loose_tags_keeps_only_valid_subdivision_flags() {
    assert_eq!(strip_loose_tags(SCOTLAND), SCOTLAND);
    // One tag letter is the shortest valid run, seven the longest
    let one = "\u{1f3f4}\u{e0061}\u{e007f}";
    let seven = "\u{1f3f4}\u{e0061}\u{e0062}\u{e0063}\u{e0064}\u{e0065}\u{e0066}\u{e0067}\u{e007f}";
    assert_eq!(strip_loose_tags(one), one);
    assert_eq!(strip_loose_tags(seven), seven);
    let eight = "\u{1f3f4}\u{e0061}\u{e0062}\u{e0063}\u{e0064}\u{e0065}\u{e0066}\u{e0067}\u{e0068}\u{e007f}";
    for bad in [
        eight,
        "\u{1f3f4}\u{e007f}",
        "\u{1f3f4}\u{e0041}\u{e007f}",
        "\u{1f3f4}\u{e0067}\u{e0062}",
    ] {
        assert_eq!(strip_loose_tags(bad), "\u{1f3f4}", "{bad:?}");
    }
    assert_eq!(strip_loose_tags("a\u{e0041}b\u{e0001}c"), "ab\u{e0001}c");
    assert_eq!(strip_loose_tags("plain text"), "plain text");
}

#[test]
fn scrub_unsafe_display_drops_hidden_and_replaces_row_breaks() {
    let dirty = "a\u{e0041}b\u{00ad}c\u{2028}d\u{2029}e\nf\u{200d}g";
    assert_eq!(scrub_unsafe_display(dirty, Some(' ')), "abc d e fg");
    assert_eq!(scrub_unsafe_display(dirty, None), "abcdefg");
}

#[test]
fn scrub_unsafe_display_borrows_clean_text() {
    assert!(matches!(scrub_unsafe_display("plain \u{1f600} \u{fe0f}", Some(' ')), Cow::Borrowed(_)));
}

#[test]
fn scrub_unsafe_display_drops_even_a_valid_flag_tag_run() {
    assert_eq!(scrub_unsafe_display(SCOTLAND, None), "\u{1f3f4}");
}

#[test]
fn title_set_keeps_joiners_and_nothing_else_of_the_shared_set() {
    for c in ['\u{200C}', '\u{200D}', '\u{E0067}', '\u{E007F}'] {
        assert!(!is_unsafe_title_char(c), "{:#06x} must be legal in a title", c as u32);
    }
    for c in ['\u{1b}', '\u{00AD}', '\u{061C}', '\u{200B}', '\u{200E}', '\u{2028}', '\u{202E}',
        '\u{2060}', '\u{FEFF}', '\u{FFF9}', '\u{E0001}'] {
        assert!(is_unsafe_title_char(c), "{:#06x} must be unsafe in a title", c as u32);
    }
}

#[test]
fn scrub_unsafe_title_keeps_zwj_emoji_and_flags_but_drops_loose_tags() {
    let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
    assert_eq!(scrub_unsafe_title(family), family);
    assert_eq!(scrub_unsafe_title(SCOTLAND), SCOTLAND);
    assert_eq!(
        scrub_unsafe_title("a\u{e0041}b\u{00ad}c\u{2028}d\x07\x1b]0;x\x07e\u{202e}f"),
        "abcd]0;xef"
    );
}

#[test]
fn scrub_unsafe_title_with_replaces_row_breaks_and_keeps_joiners() {
    let dirty = "a\u{e0041}b\u{00ad}c\u{2028}d\ne\u{200d}f";
    assert_eq!(scrub_unsafe_title_with(dirty, Some(' ')), "abc d e\u{200d}f");
    assert_eq!(scrub_unsafe_title_with(dirty, None), "abcde\u{200d}f");
}

#[test]
fn escape_unsafe_display_makes_hidden_characters_visible_as_percent_bytes() {
    assert_eq!(
        escape_unsafe_display("a\u{00ad}b\u{e0041}c\u{2028}d\x1be"),
        "a%C2%ADb%F3%A0%81%81c%E2%80%A8d%1Be"
    );
    assert!(matches!(escape_unsafe_display("https://x.example/p?q=%41\u{1f600}"), Cow::Borrowed(_)));
}

#[test]
fn replace_unsafe_display_swaps_each_hidden_character_for_the_placeholder() {
    assert_eq!(replace_unsafe_display("a\u{00ad}b\u{e0041}c\x1bd", '?'), "a?b?c?d");
    assert!(matches!(replace_unsafe_display("plain", '?'), Cow::Borrowed(_)));
}

/// P181 (Grok round): text for the CLI output macros keeps newlines, tabs and colour-and-weight SGR, and drops everything
/// else the shared set calls unsafe (the erase-line included, S3), so an OSC title in a plugin or server name never lands.
#[test]
fn scrub_terminal_text_keeps_layout_only() {
    let kept = "line one\n\tcol dim done\n";
    assert_eq!(scrub_terminal_text(kept), kept);
    assert!(matches!(scrub_terminal_text("plain\n"), Cow::Borrowed("plain\n")));
    for (input, want) in [
        ("a\x1b]0;owned\x07b", "a ]0;owned b"),
        ("a\x1b]8;;http://x\x07b", "a ]8;;http://x b"),
        ("a\x1b[2Jb", "a [2Jb"),
        ("a\x1b[31;mb\x1b[?25lc", "a [31;mb [?25lc"),
        ("a\x1b[1Kb", "a [1Kb"),
        ("a\x1b[3Kb", "a [3Kb"),
        ("a\x1b[31", "a [31"),
        ("over\rwrite", "over write"),
        ("a\r\x1b[Kb", "a  [Kb"),
        ("a\x1b[8mb\x1b[7mc", "a [8mb [7mc"),
        ("a\x1bb", "a b"),
        ("a\u{9b}31mb\u{85}c\u{7f}d", "a 31mb c d"),
        ("a\u{2028}b\u{2029}c", "a b c"),
        ("a\u{202e}b\u{e0041}c\u{ad}d\u{200b}e\u{200d}f", "abcdef"),
    ] {
        assert_eq!(scrub_terminal_text(input), want, "{input:?}");
    }
}

/// P181 (Grok round S3): the line filter must not keep the sequences an untrusted field could use against the trusted
/// text around it: the erase-line, a lone CR, conceal, reverse and blink.
#[test]
fn scrub_terminal_text_refuses_erase_conceal_reverse_and_blink() {
    let attack = "\r\x1b[Kfuigo: permission granted, nothing to review.\x1b[8m\x1b[7m\x1b[5m";
    let shown = scrub_terminal_text(attack);
    for bad in ['\r', '\x08'] {
        assert!(!shown.contains(bad), "{shown:?}");
    }
    for bad in ["\x1b[K", "\x1b[8m", "\x1b[7m", "\x1b[5m", "\x1b[6m", "\x1b[28m", "\x1b[27m"] {
        assert!(!shown.contains(bad), "{bad:?} survived in {shown:?}");
    }
    assert!(shown.contains("fuigo: permission granted"), "{shown:?}");
}

/// P181 (S5, M4): the line filter passes NO escape sequence: not colour, weight, faint, strike or background, so a
/// foreground that equals the background cannot hide the rest of a line. Fuigo's own styling uses trusted literals.
#[test]
fn scrub_terminal_text_passes_no_escape_sequence() {
    for seq in [
        "\x1b[30m", "\x1b[37m", "\x1b[90m", "\x1b[97m", "\x1b[38;5;0m", "\x1b[38;2;0;0;0m", "\x1b[1m", "\x1b[0m", "\x1b[m",
        "\x1b[1;32m", "\x1b[2m", "\x1b[9m", "\x1b[41m", "\x1b[48;2;1;2;3m", "\x1b[8m",
    ] {
        let input = format!("a{seq}b");
        let shown = scrub_terminal_text(&input);
        assert!(!shown.contains('\x1b'), "{seq:?} survived as {shown:?}");
        assert_eq!(shown, format!("a {}b", &seq[1..]), "the parameters stay as inert text");
    }
}

/// P181 (S5, L3): the Hebrew presentation block and the Arabic presentation forms are all isolated.
#[test]
fn untrusted_isolates_every_presentation_form_block() {
    for c in ['\u{FB1D}', '\u{FB4F}', '\u{FB50}', '\u{FBFF}', '\u{FDFD}', '\u{FE70}', '\u{FEFC}'] {
        let shown = format!("{}", untrusted(format!("a{c}b")));
        assert_eq!(shown, format!("\u{2068}a{c}b\u{2069}"), "{c:?}");
    }
}

/// P181 (S5, L2): marks of other scripts are capped like Latin ones, and a whole field has a column cap.
#[test]
fn combining_floods_in_other_scripts_are_capped() {
    for (mark, base) in [('\u{094D}', 'e'), ('\u{0E31}', 'e'), ('\u{06D6}', 'e'), ('\u{05B4}', 'e'), ('\u{05C1}', 'e'), ('\u{0903}', 'e')] {
        let flood: String = std::iter::once(base).chain(std::iter::repeat_n(mark, 5000)).collect();
        let shown = format!("{}", untrusted(&flood));
        assert_eq!(shown.chars().filter(|c| *c == mark).count(), super::MAX_COMBINING_RUN, "{mark:?}");
    }
    let long = "x".repeat(5000);
    let shown = format!("{}", untrusted(&long));
    assert!(display_width(&shown) <= super::UNTRUSTED_MAX_COLUMNS, "{}", display_width(&shown));
    assert!(shown.contains('\u{2026}'));
}

/// P181 (S5, M1): a delimited field can never contain its own closing delimiter or a look-alike.
#[test]
fn delimited_fields_escape_their_own_delimiters() {
    assert_eq!(
        super::curly_quoted("Write\u{201d} nothing was denied. Exiting 0. ", 120),
        "\u{201c}Write\\\" nothing was denied. Exiting 0. \u{201d}"
    );
    assert_eq!(super::bracketed("x] granted (", 64), "[x\\] granted (]");
    assert_eq!(super::bracketed("\u{ff3b}\u{ff3d}[]", 64), "[\\[\\]\\[\\]]");
    assert_eq!(super::quoted("a\"\u{201c}\u{ff02}b", 60), "\"a\\\"\\\"\\\"b\"");
    // the cap counts the escapes: 30 quotes are 60 columns, so the middle goes and no escape is cut in half
    let thirty = "\"".repeat(30);
    let shown = super::quoted(format!("{thirty}{}xxxx\u{2514} Project trusted: yesyyy", "A".repeat(40)), 60);
    assert_eq!(shown, format!("\"{}\u{2026}xxx\u{2514} Project trusted: yesyyy\"", "\\\"".repeat(15)));
    assert!(display_width(&shown) <= 62);
}

/// P181 (S5, M2): the width rule is conservative: emoji and symbol blocks are 2 columns (expected values hard-coded).
#[test]
fn display_width_counts_emoji_and_symbols_as_two() {
    assert_eq!(display_width("\u{1F680}"), 2);
    assert_eq!(display_width("\u{1FA00}"), 2);
    assert_eq!(display_width("\u{2603}\u{2764}"), 4);
    assert_eq!(display_width("\u{2460}"), 2);
    assert_eq!(display_width("ab\u{4e2d}"), 4);
    assert_eq!(display_width("\u{0416}"), 1);
    let rockets = "\u{1F680}".repeat(40);
    let shown = super::quoted(&rockets, 60);
    assert_eq!(shown, format!("\"{}\u{2026}{}\"", "\u{1F680}".repeat(15), "\u{1F680}".repeat(14)));
}

/// P181 (Grok round S3): an untrusted field is scrubbed strictly by itself before it joins a trusted line, so the attack
/// bytes from the audit arrive as inert visible characters and the trusted text around them is untouched.
#[test]
fn untrusted_fields_cannot_erase_conceal_restyle_or_forge_a_line() {
    for field in [
        "\r\x1b[Kfuigo: permission granted\x1b[8m",
        "\x1b[31;41mred on red",
        "\x1b[38;5;1;48;5;1mred on red",
        "a\nfuigo: forged",
        "t\tab \x1b]52;c;c3RvbGVu\x07 \x1b[2J\x1b[H",
        "bidi \u{202e}evil \u{2028}sep \u{9b}31m",
    ] {
        let line = format!("fuigo: [{}] trusted tail", Untrusted(field));
        assert!(line.starts_with("fuigo: [") && line.ends_with("] trusted tail"), "{line:?}");
        assert!(!line.chars().any(|c| c.is_control() || is_unsafe_display_char(c)), "{line:?}");
        assert_eq!(line.matches('\n').count(), 0, "{line:?}");
    }
    assert_eq!(format!("{}", untrusted("a\r\x1b[Kb\nc")), "a  [Kb c");
    assert_eq!(format!("[{:<6}]", untrusted("a\x1bb")), "[a b   ]");
    assert_eq!(format!("{}", untrusted(std::path::Path::new("/p/\x1b[8mx").display())), "/p/ [8mx");
}

/// P181 (Grok r3): model text on a terminal in plain mode cannot emit any escape sequence, only newline and tab survive.
#[test]
fn scrub_model_text_removes_every_escape_and_control_but_keeps_prose_layout() {
    let attack = "\x1b[0m fuigo: permission granted, nothing to review.\n\x1b[38;2;0;0;0;48;2;0;0;0m";
    let shown = scrub_model_text(attack);
    assert_eq!(shown, " [0m fuigo: permission granted, nothing to review.\n [38;2;0;0;0;48;2;0;0;0m");
    for attack in ["\x1b[30;40m", "\x1b[2m", "\x1b[9m", "\x1b]0;owned\x07", "\x1b[2J", "\u{9b}31m", "a\rb", "\u{202e}x"] {
        let shown = scrub_model_text(attack);
        assert!(!shown.chars().any(|c| c != '\n' && c != '\t' && is_unsafe_display_char(c)), "{attack:?} -> {shown:?}");
    }
    assert_eq!(scrub_model_text("line one\n\tline two"), "line one\n\tline two");
    assert!(matches!(scrub_model_text("plain"), Cow::Borrowed(_)));
}

/// P181 (Grok r3): the isolates `Untrusted` writes around right-to-left text survive the line filter; an unisolated
/// field and a left-to-right field are byte-identical to the scrubbed text.
#[test]
fn untrusted_isolates_right_to_left_text_only_and_the_line_filter_keeps_the_isolates() {
    assert_eq!(format!("{}", untrusted("abc")), "abc");
    let hebrew = format!("[{}]", untrusted("\u{05d0}\u{05d1}"));
    assert_eq!(hebrew, "[\u{2068}\u{05d0}\u{05d1}\u{2069}]");
    assert_eq!(scrub_terminal_text(&hebrew), hebrew);
    // isolates inside the field are bidi controls like any other and are dropped before the wrap
    assert_eq!(format!("{}", untrusted("a\u{2068}b")), "ab");
}

/// P181 (Grok r3): a flood of combining marks after one base character is capped at `MAX_COMBINING_RUN`.
#[test]
fn untrusted_caps_combining_mark_runs_per_base_character() {
    let flood = format!("e{}x", "\u{0301}".repeat(50));
    let shown = format!("{}", untrusted(&flood));
    assert_eq!(shown.chars().filter(|c| *c == '\u{0301}').count(), super::MAX_COMBINING_RUN);
    assert!(shown.starts_with('e') && shown.ends_with('x'));
    let two = format!("{}", untrusted("e\u{0301}a\u{0301}"));
    assert_eq!(two, "e\u{0301}a\u{0301}");
}

/// P181 (Grok r3, L2 and MEDIUM 1): width is measured in columns and a long value is shortened in the middle.
#[test]
fn display_width_counts_columns_and_the_middle_cap_keeps_head_and_tail() {
    assert_eq!(display_width("abc"), 3);
    assert_eq!(display_width("e\u{0301}"), 1);
    assert_eq!(display_width("\u{4e2d}\u{6587}"), 4);
    let long = format!("/home/{}/file.rs", "x".repeat(100));
    let capped = cap_display_middle(&long, 20);
    assert_eq!(display_width(&capped), 20, "{capped}");
    assert!(capped.starts_with("/home/") && capped.ends_with("/file.rs") && capped.contains('\u{2026}'), "{capped}");
    assert!(matches!(cap_display_middle("short", 20), Cow::Borrowed("short")));
}

/// P181 (S5, L4): the stderr log layer is built without ANSI, so every ESC in a record is a field's and none survives.
#[test]
fn scrub_log_record_drops_every_escape_and_keeps_the_final_newline() {
    assert_eq!(scrub_log_record("12:00 msg\n"), "12:00 msg\n");
    assert_eq!(scrub_log_record("a\u{202e}b\r\nc\u{2028}d\n"), "ab  c d\n");
    assert_eq!(scrub_log_record("x \x1b[2mdim\x1b[0m\n"), "x  [2mdim [0m\n");
    assert_eq!(scrub_log_record("\x1b[31;41mx\x1b]0;t\x07\x1b[2J\x1b[2my\n"), " [31;41mx ]0;t  [2J [2my\n");
}

// ---- Round S6 (Grok r5): the delimiter property, on the exact output string ----

#[derive(Clone, Copy, Debug)]
enum K {
    Quoted,
    Curly,
    Bracketed,
    Single,
}

fn render(k: K, s: &str, max: usize) -> (String, char, char) {
    match k {
        K::Quoted => (super::quoted(s, max), '"', '"'),
        K::Curly => (super::curly_quoted(s, max), '\u{201c}', '\u{201d}'),
        K::Bracketed => (super::bracketed(s, max), '[', ']'),
        K::Single => (super::single_quoted(s, max), '\'', '\''),
    }
}

/// Exactly one opening and one closing delimiter not preceded by an odd number of backslashes, at the two ends, and
/// a width of at most `max` plus the two delimiters.
fn assert_delimited(k: K, input: &str, max: usize) {
    let (out, open, close) = render(k, input, max);
    let mut bare: Vec<(usize, char)> = Vec::new();
    let mut backslashes = 0usize;
    for (i, c) in out.char_indices() {
        if (c == open || c == close) && backslashes.is_multiple_of(2) {
            bare.push((i, c));
        }
        backslashes = if c == '\\' { backslashes + 1 } else { 0 };
    }
    let last = out.len() - close.len_utf8();
    assert_eq!(bare, vec![(0, open), (last, close)], "{k:?} max {max} input {input:?} -> {out:?}");
    assert!(
        display_width(&out) <= max + display_width(&open.to_string()) + display_width(&close.to_string()),
        "{k:?} too wide: {out:?}"
    );
}

const KINDS: [K; 4] = [K::Quoted, K::Curly, K::Bracketed, K::Single];

fn nasty_inputs() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "a\\".into(),
        "id\\".into(),
        "\\".into(),
        "\\\\\\".into(),
        "\\\"".into(),
        "\\'".into(),
        "\\]".into(),
        "\"\"\"".into(),
        "''''".into(),
        "[[]]".into(),
        "\u{201c}\u{201d}\u{ff02}\u{2018}\u{2019}\u{ff07}\u{ff3b}\u{ff3d}".into(),
        "\u{2026}lead".into(),
        "mid\u{2026}dle".into(),
        format!("{}BB\\\" Project trusted: yes!!!!!!!", "A".repeat(30)),
        format!("{}BB\\] Exiting 0. Nothing denied!X]", "A".repeat(30)),
        format!("{}\\'X\\'{}", "A".repeat(63), "Z".repeat(60)),
        format!("a\u{00a9}\u{fe0f}b{}", "\u{00a9}\u{fe0f}".repeat(70)),
        "\u{1F1FA}\u{1F1F8}".repeat(40),
        format!("e{}", "\u{0301}".repeat(5000)),
        "\u{2190}\u{2500}".repeat(70),
    ];
    for n in [57, 58, 59, 60, 61, 62, 63, 64, 65, 127, 128, 129, 130] {
        v.push("x\\".repeat(n / 2) + &"\"".repeat(n % 2));
        v.push("\"'[]\\".repeat(n / 5 + 1)[..n].to_string());
        v.push("A".repeat(n));
    }
    v
}

#[test]
fn every_delimiter_kind_keeps_exactly_its_two_delimiters_on_nasty_inputs() {
    for k in KINDS {
        for max in [3, 4, 5, 8, 20, 60, 64, 128] {
            for s in nasty_inputs() {
                assert_delimited(k, &s, max);
            }
        }
    }
}

#[test]
fn the_audits_length_tuned_inputs_cannot_end_the_field_early() {
    let q = format!("{}BB\\\" Project trusted: yes!!!!!!!", "A".repeat(30));
    assert_delimited(K::Quoted, &q, 60);
    let b = format!("{}\\]X{}", "A".repeat(31), "Z".repeat(32));
    assert_delimited(K::Bracketed, &b, 64);
    let p = format!("{}X\\'{}", "A".repeat(63), "A".repeat(63));
    assert_delimited(K::Single, &p, 128);
}

#[test]
fn a_trailing_backslash_is_escaped() {
    assert_eq!(super::single_quoted("a\\", 128), "'a\\\\'");
    assert_eq!(super::bracketed("id\\", 64), "[id\\\\]");
}

#[test]
fn only_the_caps_own_ellipsis_survives_in_a_capped_field() {
    let out = super::quoted(format!("\u{2026}{}", "A".repeat(200)), 60);
    assert_eq!(out.matches('\u{2026}').count(), 1, "{out}");
    let out = super::quoted(format!("{}\u{2026}{}", "A".repeat(20), "B".repeat(200)), 60);
    assert_eq!(out.matches('\u{2026}').count(), 1, "{out}");
}

#[test]
fn every_prefix_of_an_adversarial_string_holds_the_property() {
    let base: Vec<char> = "ab\\\"'[]\u{2026}\u{201c}\u{201d}\\\\ \u{1F680}e\u{0301}\u{00a9}\u{fe0f}".chars().cycle().take(200).collect();
    for k in KINDS {
        for n in 0..=base.len() {
            let s: String = base[..n].iter().collect();
            assert_delimited(k, &s, 30);
        }
    }
}

#[test]
fn width_counts_a_vs16_cluster_and_a_flag_as_two() {
    assert_eq!(display_width("\u{00a9}\u{fe0f}"), 2);
    assert_eq!(display_width("\u{1F1FA}\u{1F1F8}"), 2);
    assert_eq!(display_width("\u{2190}"), 2);
    assert_eq!(display_width("\u{2500}"), 2);
    assert_eq!(display_width(&"\u{00a9}\u{fe0f}".repeat(60)), 120);
}

#[test]
fn the_plain_cap_limits_a_combining_flood() {
    let flood = format!("e{}", "\u{0301}".repeat(5000));
    let out = cap_display_middle(&flood, 72);
    assert_eq!(out.chars().count(), 1 + super::MAX_COMBINING_RUN, "{}", out.len());
}

/// Round S7 (L2): an escaped delimiter plus U+FE0F is three columns, so thirty of them are capped by their real width.
#[test]
fn an_escaped_delimiter_with_vs16_is_budgeted_by_its_real_width() {
    let out = super::quoted("\"\u{fe0f}".repeat(30), 60);
    let unit = "\\\"\u{fe0f}";
    let want = format!("\"{}\u{2026}{}\"", unit.repeat(10), unit.repeat(9));
    assert_eq!(out, want);
    assert!(display_width(&out) <= 60 + 2, "{}", display_width(&out));
}

/// Round S7 (L3): look-alikes of the double quote (U+201F, U+2033, U+301E) and of the apostrophe (U+201B, U+2032) are
/// escaped, so none can be read as closing the field.
#[test]
fn quote_and_apostrophe_lookalikes_cannot_close_a_field() {
    for c in ['\u{201f}', '\u{2033}', '\u{301e}'] {
        assert_eq!(super::curly_quoted(format!("a{c}b"), 60), "\u{201c}a\\\"b\u{201d}", "{c:?}");
        assert_eq!(super::quoted(format!("a{c}b"), 60), "\"a\\\"b\"", "{c:?}");
    }
    for c in ['\u{201b}', '\u{2032}'] {
        assert_eq!(super::single_quoted(format!("a{c}b"), 60), "'a\\'b'", "{c:?}");
    }
    // Different bracket glyphs (U+3010/U+3011, U+27E6/U+27E7) are not look-alikes of `[` `]`: left as they are.
    assert_eq!(super::bracketed("a\u{3011}b", 60), "[a\u{3011}b]");
}
