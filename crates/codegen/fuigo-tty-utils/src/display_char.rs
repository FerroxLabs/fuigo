//! Characters that are unsafe to show from untrusted text.

use std::borrow::Cow;

/// True for a character unsafe to render from untrusted or server-supplied text.
/// Controls can inject terminal escapes, invisible format characters (Unicode Cf) hide or reorder text,
/// and line separators break a row. The prepended concatenation marks are Cf too but render visibly, so they stay.
pub fn is_unsafe_display_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
        )
}

/// Keeps tags only in a subdivision flag (black flag, 1 to 7 tag letters or digits, cancel tag); others hide text.
/// Callers that must let a flag emoji through (renames, titles) run this before dropping the rest of the unsafe set.
pub fn strip_loose_tags(text: &str) -> String {
    let is_tag = |c: char| ('\u{e0020}'..='\u{e007f}').contains(&c);
    let is_flag_tag = |c: char| matches!(c, '\u{e0030}'..='\u{e0039}' | '\u{e0061}'..='\u{e007a}');
    let chars: Vec<char> = text.chars().collect();
    let mut kept = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(&character) = chars.get(at) {
        at += 1;
        if is_tag(character) {
            continue;
        }

        kept.push(character);
        if character != '\u{1f3f4}' {
            continue;
        }

        let run: Vec<char> = chars
            .iter()
            .skip(at)
            .take_while(|&&c| is_tag(c))
            .copied()
            .collect();
        let valid = matches!(run.split_last(), Some((&'\u{e007f}', letters))
            if (1..=7).contains(&letters.len()) && letters.iter().all(|&c| is_flag_tag(c)));
        if valid {
            kept.extend(&run);
        }
        at += run.len();
    }
    kept
}

/// Characters that break a row rather than hide text: controls and the Unicode line and paragraph separators.
/// A scrub replaces these with the caller's chosen filler so neighbouring words stay apart.
fn is_row_break(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

/// Scrubs untrusted text for a single-row display surface (toast, status segment, label, notice).
/// Row breaks (controls, line and paragraph separators) become `break_replacement`, or vanish when it is `None`.
/// Every other unsafe character (invisible format characters, loose tags) is dropped, with no exception.
/// Borrows the input when it is already clean, so the per-frame call on clean text does not allocate.
pub fn scrub_unsafe_display(text: &str, break_replacement: Option<char>) -> Cow<'_, str> {
    if !text.chars().any(is_unsafe_display_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_row_break(c) {
            out.extend(break_replacement);
        } else if !is_unsafe_display_char(c) {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// True for a character unsafe in a terminal title or tab title: the shared set, minus the two joiners that emoji
/// sequences need (ZWJ, ZWNJ) and minus the tag block, which [`strip_loose_tags`] has already judged.
pub fn is_unsafe_title_char(c: char) -> bool {
    is_unsafe_display_char(c)
        && !matches!(c, '\u{200C}' | '\u{200D}' | '\u{E0020}'..='\u{E007F}')
}

/// Scrubs untrusted text for a terminal title: controls and invisible characters are dropped, loose tags are dropped,
/// but ZWJ emoji sequences and valid subdivision flags (England, Scotland, Wales) survive.
pub fn scrub_unsafe_title(text: &str) -> String {
    scrub_unsafe_title_with(text, None)
}

/// [`scrub_unsafe_title`] for a row that shows a title (a goal's objective): row breaks become `break_replacement`
/// instead of vanishing, so neighbouring words stay apart.
pub fn scrub_unsafe_title_with(text: &str, break_replacement: Option<char>) -> String {
    let mut out = String::with_capacity(text.len());
    for c in strip_loose_tags(text).chars() {
        if is_row_break(c) {
            out.extend(break_replacement);
        } else if !is_unsafe_title_char(c) {
            out.push(c);
        }
    }
    out
}

/// Replaces each unsafe character with `placeholder`, so a path or message shows that something was there without
/// changing its length or its words. Borrows when the text is already clean.
pub fn replace_unsafe_display(text: &str, placeholder: char) -> Cow<'_, str> {
    if !text.chars().any(is_unsafe_display_char) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| if is_unsafe_display_char(c) { placeholder } else { c })
            .collect(),
    )
}

/// Makes unsafe characters visible instead of deleting them: each becomes its percent-encoded UTF-8 bytes (`%C2%AD`).
/// For text a person copies out of the terminal (a sign-in URL, a path), where deleting a character would change what
/// the copy means and hiding it would let it ride along unseen. Borrows when the text is already clean.
pub fn escape_unsafe_display(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_unsafe_display_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    let mut utf8 = [0u8; 4];
    for c in text.chars() {
        if is_unsafe_display_char(c) {
            for byte in c.encode_utf8(&mut utf8).bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
#[path = "display_char_tests.rs"]
mod tests;

/// A value written by someone other than Fuigo (a tool, a model, a file, a config, a session file, the network, a plugin
/// or MCP server) interpolated into user-facing terminal output. Displaying it applies the strict field scrub
/// ([`scrub_unsafe_display`] with a space for every row break): no escape byte, no CR or LF, no tab, no C0 or C1 control,
/// no bidi or invisible format character, so the value cannot erase, restyle, hide or forge a line of Fuigo's own text.
/// The whole-line filter [`scrub_terminal_text`] is only a backstop; this wrapper is the boundary for interpolated data.
/// Padding and precision apply to the scrubbed text. Use it for every `{}` in `cli_println!`, `cli_eprintln!`,
/// `display_stdout()` and terminal `writeln!` whose value Fuigo did not write itself.
pub struct Untrusted<T>(pub T);

/// [`Untrusted`] for a value printed to stdout on purpose as data (the CAPTURE path: trace export paths, the upload URL) (a path or URL a script captures): exact when stdout is
/// a pipe or file, so the capture is unchanged, and strictly scrubbed when stdout is a terminal, where a person reads it.
pub struct UntrustedStdoutData<T>(pub T);

pub fn untrusted_stdout_data<T: std::fmt::Display>(value: T) -> UntrustedStdoutData<T> {
    UntrustedStdoutData(value)
}

impl<T: std::fmt::Display> std::fmt::Display for UntrustedStdoutData<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::io::IsTerminal;
        if std::io::stdout().is_terminal() {
            std::fmt::Display::fmt(&Untrusted(&self.0), f)
        } else {
            std::fmt::Display::fmt(&self.0, f)
        }
    }
}

/// Shorthand for [`Untrusted`], so a call site reads `{}` with `untrusted(path.display())`.
pub fn untrusted<T: std::fmt::Display>(value: T) -> Untrusted<T> {
    Untrusted(value)
}

/// Overall display-width cap of one [`Untrusted`] value (middle replaced by U+2026): wide enough for any real path or
/// message, small enough that a flood in one field cannot fill the screen. Delimited fields use a much tighter cap.
pub const UNTRUSTED_MAX_COLUMNS: usize = 2048;

/// Delimiter class of a field set off by Fuigo's own punctuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delim {
    /// Double quotes: ASCII, curly U+201C/U+201D, U+201F, U+2033, U+301E and fullwidth U+FF02 are all escaped.
    Quote,
    /// Square brackets: `[` `]` and fullwidth U+FF3B/U+FF3D are escaped.
    Bracket,
    /// Single quotes: ASCII, curly U+2018/U+2019, U+201B, U+2032 and fullwidth U+FF07 are escaped.
    Apostrophe,
}

fn delim_escape(c: char, d: Delim) -> Option<&'static str> {
    match (d, c) {
        (Delim::Quote, '\u{201C}' | '\u{201D}' | '\u{201F}' | '\u{2033}' | '\u{301E}' | '"' | '\u{FF02}') => Some("\\\""),
        (Delim::Apostrophe, '\'' | '\u{2018}' | '\u{2019}' | '\u{201B}' | '\u{2032}' | '\u{FF07}') => Some("\\'"),
        (Delim::Bracket, '[' | '\u{FF3B}') => Some("\\["),
        (Delim::Bracket, ']' | '\u{FF3D}') => Some("\\]"),
        _ => None,
    }
}

/// THE helper for a field between Fuigo's own delimiters (denial title, call id, resume-conflict and sandbox-note
/// fields, the inspect `"..."` fields). Order: strict scrub, combining cap, user U+2026 becomes three dots, split into
/// UNITS (one per cluster: base plus its marks; the unit text is the escaped form, `\\` for a backslash first, then
/// the delimiter and its look-alikes, and the unit width is the width of that escaped text), middle-cap over whole
/// units to `max_columns` (head + U+2026 + tail; a unit is never split, so no escape pair is cut and no repair step
/// exists), isolate right-to-left text, wrap in `open`/`close`. Property: the output holds exactly one opening and
/// one closing delimiter that is not preceded by an odd number of backslashes, at the two ends, and its width is at
/// most `max_columns` plus the two delimiters. The delimiters are not counted in `max_columns`.
pub fn delimited<T: std::fmt::Display>(value: T, d: Delim, open: &str, close: &str, max_columns: usize) -> String {
    let raw = value.to_string();
    let clean = scrub_unsafe_display(&raw, Some(' '));
    let body = cap_core(&clean, Some(d), max_columns, true);
    if body.chars().any(is_rtl_char) {
        format!("{open}{FSI}{body}{PDI}{close}")
    } else {
        format!("{open}{body}{close}")
    }
}

/// `"..."` with ASCII quotes; see [`delimited`].
pub fn quoted<T: std::fmt::Display>(value: T, max_columns: usize) -> String {
    delimited(value, Delim::Quote, "\"", "\"", max_columns)
}

/// `'...'` with ASCII single quotes; see [`delimited`].
pub fn single_quoted<T: std::fmt::Display>(value: T, max_columns: usize) -> String {
    delimited(value, Delim::Apostrophe, "'", "'", max_columns)
}

/// Curly quotes U+201C/U+201D; see [`delimited`].
pub fn curly_quoted<T: std::fmt::Display>(value: T, max_columns: usize) -> String {
    delimited(value, Delim::Quote, "\u{201c}", "\u{201d}", max_columns)
}

/// `[...]`; see [`delimited`].
pub fn bracketed<T: std::fmt::Display>(value: T, max_columns: usize) -> String {
    delimited(value, Delim::Bracket, "[", "]", max_columns)
}

/// An undelimited untrusted field capped to `max_columns` display columns (all of [`Untrusted`], tighter cap).
pub fn capped<T: std::fmt::Display>(value: T, max_columns: usize) -> String {
    let s = Untrusted(value).to_string();
    cap_display_middle(&s, max_columns).into_owned()
}

impl<T: std::fmt::Display> std::fmt::Display for Untrusted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        let raw = self.0.to_string();
        let clean = scrub_unsafe_display(&raw, Some(' '));
        let marks = cap_combining(&clean);
        let scrubbed = cap_display_middle(&marks, UNTRUSTED_MAX_COLUMNS);
        if scrubbed.chars().any(is_rtl_char) {
            // Right-to-left text is isolated so it cannot reorder the label around it. Left-to-right text (every
            // pipe, log and JSON field in practice) is written exactly as before, with no extra character.
            f.write_char(FSI)?;
            f.pad(&scrubbed)?;
            f.write_char(PDI)
        } else {
            f.pad(&scrubbed)
        }
    }
}

impl<T: std::fmt::Display> std::fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Scrubs text bound for a terminal through the CLI output macros (`cli_println!`, `cli_eprintln!` and the stderr line
/// writers). This is a backstop, NOT the boundary for interpolated data: a value Fuigo did not write must be wrapped in
/// [`Untrusted`] before it joins a line, because the layout this filter keeps (newline, tab) is exactly what an
/// untrusted field could use to forge a line. What survives is newline and tab. NO escape sequence passes (round S5:
/// no colour, weight or any SGR, since a foreground equal to the background hides the rest of a line); the ESC byte
/// becomes a space and its parameters show as inert text. Every other control, C1, a lone CR and the line separators becomes
/// a space; hidden format characters go. Fuigo's own styling, erase-line and cursor control go through
/// [`crate::cli_eprint_trusted`] (trusted literals) around scrubbed text.
/// Borrows the input when nothing needs changing, so the per-line call on clean text does not allocate.
pub fn scrub_terminal_text(text: &str) -> Cow<'_, str> {
    let layout = |c: char| c == '\n' || c == '\t';
    if !text.chars().any(|c| is_unsafe_display_char(c) && !layout(c) && !is_isolate(c)) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(c) = rest.chars().next() {
        rest = &rest[c.len_utf8()..];
        if layout(c) || is_isolate(c) {
            out.push(c);
        } else if is_row_break(c) {
            out.push(' ');
        } else if !is_unsafe_display_char(c) {
            out.push(c);
        }
    }
    Cow::Owned(out)
}


/// First-strong isolate and pop-directional-isolate: the only bidi characters Fuigo writes itself.
const FSI: char = '\u{2068}';
const PDI: char = '\u{2069}';

fn is_isolate(c: char) -> bool {
    c == FSI || c == PDI
}

/// Most combining marks kept after one base character in [`Untrusted`] output; the rest of the run is dropped.
pub const MAX_COMBINING_RUN: usize = 4;

fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05BD}'
            | '\u{05BF}' | '\u{05C1}'..='\u{05C2}' | '\u{05C4}'..='\u{05C5}' | '\u{05C7}'
            | '\u{0610}'..='\u{061A}'
            | '\u{064B}'..='\u{065F}'
            | '\u{0670}'
            | '\u{06D6}'..='\u{06ED}'
            | '\u{0900}'..='\u{0903}'
            | '\u{093A}'..='\u{094F}'
            | '\u{0E31}' | '\u{0E34}'..='\u{0E3A}' | '\u{0E47}'..='\u{0E4E}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FE20}'..='\u{FE2F}'
    )
}

/// Characters with a strong right-to-left direction (Hebrew, Arabic, Syriac, Thaana, NKo and their presentation forms).
fn is_rtl_char(c: char) -> bool {
    matches!(c, '\u{0590}'..='\u{08FF}' | '\u{FB1D}'..='\u{FDFF}' | '\u{FE70}'..='\u{FEFF}' | '\u{10800}'..='\u{10FFF}' | '\u{1E800}'..='\u{1EFFF}')
}

/// Drops combining marks beyond [`MAX_COMBINING_RUN`] after one base character, so a flood cannot smear the row.
fn cap_combining(text: &str) -> Cow<'_, str> {
    let mut run = 0usize;
    let mut over = false;
    for c in text.chars() {
        if is_combining_mark(c) {
            run += 1;
            over |= run > MAX_COMBINING_RUN;
        } else {
            run = 0;
        }
    }
    if !over {
        return Cow::Borrowed(text);
    }
    let mut run = 0usize;
    Cow::Owned(
        text.chars()
            .filter(|&c| {
                if is_combining_mark(c) {
                    run += 1;
                    run <= MAX_COMBINING_RUN
                } else {
                    run = 0;
                    true
                }
            })
            .collect(),
    )
}

/// Scrubs model-authored text bound for a terminal in plain headless mode. Stricter than [`scrub_terminal_text`]:
/// no escape sequence at all (the ESC byte and every other C0 and C1 control become a space, so a pasted `[31m` is
/// shown as inert text), no bidi or invisible format character, no colour. Only newline and tab survive, because
/// they are legitimate in prose. The caller joins every chunk of a response BEFORE calling this, so a sequence split
/// across chunks is judged whole.
pub fn scrub_model_text(text: &str) -> Cow<'_, str> {
    let keep = |c: char| c == '\n' || c == '\t';
    if !text.chars().any(|c| is_unsafe_display_char(c) && !keep(c)) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if keep(c) {
            out.push(c);
        } else if is_row_break(c) {
            out.push(' ');
        } else if !is_unsafe_display_char(c) {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Terminal columns `text` occupies: 0 for combining marks and isolates, 2 for East Asian wide, every emoji block
/// (U+1F000-1FAFF) and the symbol blocks terminals draw wide or ambiguously (U+2300-23FF, enclosed alphanumerics,
/// geometric shapes, dingbats and misc symbols U+2600-27BF, U+2B00-2BFF): when in doubt it counts 2, so a cap never
/// under-measures. Greek and Cyrillic letters stay 1. Else 1.
/// An approximation without a width table (no new dependency); it is exact for ASCII, Latin, Cyrillic, Greek, Hebrew,
/// Arabic, CJK and the common emoji blocks, which is what file and server names are made of.
pub fn display_width(text: &str) -> usize {
    clusters(text).map(|(_, w)| w).sum()
}

fn is_regional_indicator(c: char) -> bool {
    matches!(c, '\u{1F1E6}'..='\u{1F1FF}')
}

/// Splits text into clusters (a base character with its following combining marks, or a regional-indicator pair),
/// each with ONE display width: U+FE0F after a base makes it 2, a flag is 2.
fn clusters(text: &str) -> impl Iterator<Item = (&str, usize)> {
    let mut it = text.char_indices().peekable();
    std::iter::from_fn(move || {
        let (start, c) = it.next()?;
        let mut width = char_width(c);
        let mut end = start + c.len_utf8();
        if is_regional_indicator(c) && it.peek().is_some_and(|&(_, n)| is_regional_indicator(n)) {
            let (i, n) = it.next()?;
            end = i + n.len_utf8();
            width = 2;
        }
        let mut vs16 = false;
        while let Some(&(i, n)) = it.peek() {
            if !is_combining_mark(n) {
                break;
            }
            vs16 |= n == '\u{FE0F}';
            end = i + n.len_utf8();
            it.next();
        }
        if vs16 {
            width = width.max(2);
        }
        Some((&text[start..end], width))
    })
}

/// One unit per cluster; with a delimiter kind the unit text is the escaped form and its width that of the escaped text.
fn build_units(text: &str, d: Option<Delim>) -> Vec<(String, usize)> {
    clusters(text)
        .map(|(cl, w)| {
            let Some(d) = d else { return (cl.to_string(), w) };
            let mut chars = cl.chars();
            let base = chars.next().unwrap_or(' ');
            let esc = if base == '\\' { Some("\\\\") } else { delim_escape(base, d) };
            match esc {
                Some(e) => {
                    let text = format!("{e}{}", chars.as_str());
                    let w = display_width(&text);
                    (text, w)
                }
                None => (cl.to_string(), w),
            }
        })
        .collect()
}

/// Shared cap: combining cap, then whole-unit middle cap (head + U+2026 + tail). A user U+2026 becomes `...` when the
/// text is capped (or always, when `always_dots`), so the only U+2026 in a capped result is the cap's own.
fn cap_core(text: &str, d: Option<Delim>, max: usize, always_dots: bool) -> String {
    let marks = cap_combining(text);
    let mut units = build_units(&marks, d);
    let mut total: usize = units.iter().map(|u| u.1).sum();
    let capping = total > max && max >= 3;
    if (always_dots || capping) && marks.contains('\u{2026}') {
        units = build_units(&marks.replace('\u{2026}', "..."), d);
        total = units.iter().map(|u| u.1).sum();
    }
    if total <= max || max < 3 {
        return units.into_iter().map(|u| u.0).collect();
    }
    let budget = max - 1;
    let (head_budget, tail_budget) = (budget.div_ceil(2), budget / 2);
    let (mut head, mut used, mut n_head) = (String::new(), 0, 0);
    for (t, w) in &units {
        if used + w > head_budget {
            break;
        }
        used += w;
        head.push_str(t);
        n_head += 1;
    }
    let (mut tail, mut used) = (Vec::new(), 0);
    for (t, w) in units[n_head..].iter().rev() {
        if used + w > tail_budget {
            break;
        }
        used += w;
        tail.push(t.as_str());
    }
    tail.reverse();
    format!("{head}\u{2026}{}", tail.concat())
}

fn char_width(c: char) -> usize {
    if is_combining_mark(c) || is_isolate(c) || is_unsafe_display_char(c) {
        0
    } else if matches!(
        c,
        '\u{1100}'..='\u{115F}'
            | '\u{2E80}'..='\u{A4CF}'
            | '\u{AC00}'..='\u{D7A3}'
            | '\u{F900}'..='\u{FAFF}'
            | '\u{FE30}'..='\u{FE6F}'
            | '\u{FF00}'..='\u{FF60}'
            | '\u{FFE0}'..='\u{FFE6}'
            | '\u{1F000}'..='\u{1FAFF}'
            | '\u{2190}'..='\u{21FF}'
            | '\u{2300}'..='\u{23FF}'
            | '\u{2460}'..='\u{24FF}'
            | '\u{2500}'..='\u{257F}'
            | '\u{25A0}'..='\u{25FF}'
            | '\u{2600}'..='\u{27BF}'
            | '\u{2B00}'..='\u{2BFF}'
            | '\u{20000}'..='\u{3FFFD}'
    ) {
        2
    } else {
        1
    }
}

/// `text` limited to `max` display columns by replacing the middle with one `\u{2026}`; the head and tail are kept
/// because the start of a path says where it is and the end says what it is.
pub fn cap_display_middle(text: &str, max: usize) -> Cow<'_, str> {
    let out = cap_core(text, None, max, false);
    if out == text { Cow::Borrowed(text) } else { Cow::Owned(out) }
}

/// Scrubs one formatted log record (a single line ending in `\n`) for a terminal log sink. tracing-subscriber 0.3.23
/// escapes ESC in a message but NOT in a field recorded with `%`. The stderr layer is built with `with_ansi(false)`,
/// so the formatter writes no style of its own and EVERY ESC in a record is a field's: each becomes a space, as does
/// every other control (CR, a LF inside the record); line and paragraph separators and bidi or invisible format
/// characters are dropped. The one trailing `\n` stays.
pub fn scrub_log_record(text: &str) -> Cow<'_, str> {
    let (body, end) = match text.strip_suffix('\n') {
        Some(body) => (body, "\n"),
        None => (text, ""),
    };
    if !body.chars().any(|c| is_unsafe_display_char(c) && c != '\t') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = body;
    while let Some(c) = rest.chars().next() {
        rest = &rest[c.len_utf8()..];
        if c == '\t' {
            out.push(c);
        } else if is_row_break(c) {
            out.push(' ');
        } else if !is_unsafe_display_char(c) {
            out.push(c);
        }
    }
    out.push_str(end);
    Cow::Owned(out)
}
