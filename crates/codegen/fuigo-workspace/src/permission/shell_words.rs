//! Quote-aware normalisation of one parsed shell word into the literal words bash would hand the program.
//!
//! The classifier and the file-effect model both match on argv words, so they must see the words bash produces, not the
//! spelling the model typed: `'r'm`, `\rm` and `r"m"` are all `rm`, and `{cat,/etc/shadow}` is two words.
//! [`normalise_word`] applies quote removal, backslash escapes, adjacent-fragment joining and unquoted brace expansion.
//! Anything it cannot pin down exactly comes back [`NormalisedWord::Unresolved`] and never as a guess: a `$` or
//! backtick expansion, an unquoted glob character that could match files, a brace expansion over [`WORD_CAP`], or a
//! malformed spelling. Braces, globs and `$` inside quotes (or escaped) are literal.

use tree_sitter::Node;

/// Strict cap on the words one brace expansion may produce, and on a sequence range's length. Over it the word is
/// unresolved; there is no placeholder value.
pub(crate) const WORD_CAP: usize = 64;

/// u35 r2: strict cap on unquoted brace nesting depth, and on the brace groups one word may expand through (the
/// recursion depth of [`brace_expand`]). Over either the word is unresolved, before any alternative is copied.
pub(crate) const BRACE_DEPTH_CAP: usize = 8;
const BRACE_GROUP_CAP: usize = 64;

/// The outcome of normalising one shell word.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NormalisedWord {
    /// The exact literal words bash produces, in order (more than one only through brace expansion).
    Words(Vec<String>),
    /// The words depend on something only the running shell knows.
    Unresolved(Unresolved),
}

/// Why a word could not be normalised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unresolved {
    /// A `$` or backtick expansion (parameter, command substitution, arithmetic, `$'...'`).
    Expansion,
    /// An unquoted `*`, `?` or `[...]` that pathname expansion could rewrite.
    Glob,
    /// A brace expansion over [`WORD_CAP`] words.
    OverCap,
    /// An unterminated quote or a trailing lone backslash.
    Malformed,
}

/// One character of the word after quote removal, with whether it was quoted (or escaped) in the source.
#[derive(Clone, Copy)]
struct Char {
    ch: char,
    quoted: bool,
}

/// What pathname expansion can do to one word bash hands the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GlobMark {
    /// No unquoted `*`, `?` or `[...]`: the word is exactly its text (a quoted glob character is literal).
    Literal,
    /// An unquoted glob whose first character is a literal other than `-` (`src/*.rs`, `./*.md`, `feat*`): every match
    /// starts with that character, so the word names a path and never becomes an option.
    Anchored,
    /// An unquoted glob that starts with a wildcard, or with `-` (`*`, `?ompress`, `-*`): a match can begin with `-`
    /// (a file named `-rf`) and become an option, or stand for any program.
    OptionCapable,
}

/// One word bash produces from a source word, with how pathname expansion can rewrite it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MarkedWord {
    /// Quotes removed, escapes folded, braces expanded; a glob word is its pattern.
    pub(crate) text: String,
    pub(crate) glob: GlobMark,
}

/// [`normalise_word_marking_globs`] over a parsed word node's source text.
pub(crate) fn normalise_word_node_marking_globs(node: Node<'_>, src: &str) -> Result<Vec<MarkedWord>, Unresolved> {
    match node.utf8_text(src.as_bytes()) {
        Ok(text) => normalise_word_marking_globs(text),
        Err(_) => Err(Unresolved::Malformed),
    }
}

/// Normalise the source spelling of one shell word (a `word`, `string`, `raw_string`, `number` or `concatenation`)
/// into the words bash produces. A glob word comes back as its pattern, marked with whether it is quoted (literal),
/// anchored on a leading literal, or able to expand into an option ([`GlobMark`]).
pub(crate) fn normalise_word_marking_globs(raw: &str) -> Result<Vec<MarkedWord>, Unresolved> {
    let literal = |text: &str| {
        Ok(vec![MarkedWord {
            text: text.to_owned(),
            glob: GlobMark::Literal,
        }])
    };
    if !raw.contains(['\\', '\'', '"', '$', '`', '{', '*', '?', '[', '~']) {
        return literal(raw);
    }
    if windows_path_like(raw) && !raw.contains(['\'', '"', '$', '`', '{', '*', '?', '[']) {
        // `C:\Users\me` keeps its separators; the permission layer resolves it as a Windows path.
        return literal(raw);
    }
    let (chars, empty_quote) = dequote(raw)?;
    // u35 r3 (Astra r2 H3): an empty quote pair leaves no character behind but still makes the word quoted where it
    // stands, so bash keeps `''~` and `{r''..r}` literal. The character model cannot hold that position: fail closed.
    if empty_quote && chars.iter().any(|c| !c.quoted && matches!(c.ch, '~' | '{')) {
        return Err(Unresolved::Expansion);
    }
    if brace_depth(&chars) > BRACE_DEPTH_CAP {
        return Err(Unresolved::OverCap);
    }
    let mut expanded = Vec::new();
    brace_expand(&chars, &mut expanded, 0)?;
    let braced = expanded.len() != 1 || expanded[0].len() != chars.len();
    let mut words = Vec::with_capacity(expanded.len());
    for word in &expanded {
        // An empty word out of a brace expansion is dropped or kept depending on quoting bash tracks per piece.
        if braced && word.is_empty() {
            return Err(Unresolved::Malformed);
        }
        let tilde = expand_tilde(word)?;
        let word = tilde.as_deref().unwrap_or(word.as_slice());
        words.push(MarkedWord {
            text: word.iter().map(|c| c.ch).collect(),
            glob: glob_mark(word),
        });
    }
    Ok(words)
}

/// Normalise one shell word. Strict: a word pathname expansion could rewrite is [`Unresolved::Glob`].
#[cfg(test)]
pub(crate) fn normalise_word(raw: &str) -> NormalisedWord {
    match normalise_word_marking_globs(raw) {
        Ok(words) if words.iter().any(|w| w.glob != GlobMark::Literal) => NormalisedWord::Unresolved(Unresolved::Glob),
        Ok(words) => NormalisedWord::Words(words.into_iter().map(|w| w.text).collect()),
        Err(reason) => NormalisedWord::Unresolved(reason),
    }
}

/// [`normalise_word`], except that a glob word comes back as its pattern.
#[cfg(test)]
pub(crate) fn normalise_word_keeping_globs(raw: &str) -> NormalisedWord {
    match normalise_word_marking_globs(raw) {
        Ok(words) => NormalisedWord::Words(words.into_iter().map(|w| w.text).collect()),
        Err(reason) => NormalisedWord::Unresolved(reason),
    }
}

/// How pathname expansion can rewrite one expanded word: only an unquoted glob character makes it a pattern, and only a
/// leading literal other than `-` keeps every match from reading as an option.
fn glob_mark(word: &[Char]) -> GlobMark {
    if !is_glob(word) {
        return GlobMark::Literal;
    }
    match word.first() {
        Some(first) if first.ch == '-' => GlobMark::OptionCapable,
        Some(first) if !first.quoted && matches!(first.ch, '*' | '?') => GlobMark::OptionCapable,
        Some(first) if !first.quoted && first.ch == '[' && word[1..].iter().any(|c| c.ch == ']') => {
            GlobMark::OptionCapable
        }
        _ => GlobMark::Anchored,
    }
}

fn windows_path_like(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    raw.starts_with("\\\\")
        || (bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':'))
}

/// u35 r1: tilde expansion (after brace expansion, as bash orders them). An unquoted leading `~` alone or before `/` is
/// `$HOME`; every other tilde prefix (`~user`, `~-`, `~+`, `~2`, or one with a quoted character) names a directory the
/// classifier cannot know, so it is unresolved. A quoted `~` is literal.
fn expand_tilde(word: &[Char]) -> Result<Option<Vec<Char>>, Unresolved> {
    if !word.first().is_some_and(|c| c.ch == '~' && !c.quoted) {
        return Ok(None);
    }
    let end = word.iter().position(|c| c.ch == '/').unwrap_or(word.len());
    if end != 1 || word.get(end).is_some_and(|slash| slash.quoted) {
        return Err(Unresolved::Expansion);
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|home| !home.is_empty())
        .ok_or(Unresolved::Expansion)?;
    let mut out: Vec<Char> = home.chars().map(|ch| Char { ch, quoted: true }).collect();
    out.extend_from_slice(&word[1..]);
    Ok(Some(out))
}

/// Quote removal and escape folding, keeping which characters were quoted, and whether an empty quote pair (`''`,
/// `""`) occurred.
fn dequote(raw: &str) -> Result<(Vec<Char>, bool), Unresolved> {
    let quoted = |ch| Char { ch, quoted: true };
    let mut out = Vec::with_capacity(raw.len());
    let mut empty_quote = false;
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some('\n') => {}
                Some(next) => out.push(quoted(next)),
                None => return Err(Unresolved::Malformed),
            },
            '\'' => {
                let start = out.len();
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(next) => out.push(quoted(next)),
                        None => return Err(Unresolved::Malformed),
                    }
                }
                empty_quote |= out.len() == start;
            }
            '"' => {
                let start = out.len();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(next @ ('$' | '`' | '"' | '\\')) => out.push(quoted(next)),
                            Some('\n') => {}
                            Some(next) => {
                                out.push(quoted('\\'));
                                out.push(quoted(next));
                            }
                            None => return Err(Unresolved::Malformed),
                        },
                        Some('$' | '`') => return Err(Unresolved::Expansion),
                        Some(next) => out.push(quoted(next)),
                        None => return Err(Unresolved::Malformed),
                    }
                }
                empty_quote |= out.len() == start;
            }
            '$' | '`' => return Err(Unresolved::Expansion),
            _ => out.push(Char { ch, quoted: false }),
        }
    }
    Ok((out, empty_quote))
}

/// The byte offset just past the character that starts at byte `at` of `text` (option clusters may hold non-ASCII).
pub(crate) fn after_char(text: &str, at: usize) -> usize {
    at + text[at..].chars().next().map_or(0, char::len_utf8)
}

/// Whether pathname expansion could rewrite the word: an unquoted `*` or `?`, or an unquoted `[` with a later `]`.
fn is_glob(word: &[Char]) -> bool {
    word.iter().enumerate().any(|(at, c)| {
        !c.quoted
            && match c.ch {
                '*' | '?' => true,
                '[' => word[at + 1..].iter().any(|later| later.ch == ']'),
                _ => false,
            }
    })
}

fn unquoted(c: &Char, ch: char) -> bool {
    !c.quoted && c.ch == ch
}

/// The deepest unquoted brace nesting in a word.
fn brace_depth(word: &[Char]) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    for c in word.iter().filter(|c| !c.quoted) {
        match c.ch {
            '{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// Bash brace expansion over unquoted braces: comma groups and `x..y[..incr]` sequences, left to right, nested groups
/// included. A group that is neither stays literal. More than [`WORD_CAP`] words, a group with more alternatives than
/// that, or more than [`BRACE_GROUP_CAP`] nested expansion steps is [`Unresolved::OverCap`].
fn brace_expand(word: &[Char], out: &mut Vec<Vec<Char>>, level: usize) -> Result<(), Unresolved> {
    if level > BRACE_GROUP_CAP {
        return Err(Unresolved::OverCap);
    }
    let mut start = 0;
    while start < word.len() {
        if !unquoted(&word[start], '{') {
            start += 1;
            continue;
        }
        let mut depth = 0usize;
        let mut commas = Vec::new();
        let mut end = None;
        for (at, c) in word.iter().enumerate().skip(start) {
            if c.quoted {
                continue;
            }
            match c.ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(at);
                        break;
                    }
                }
                ',' if depth == 1 => commas.push(at),
                _ => {}
            }
        }
        let Some(end) = end else {
            start += 1;
            continue;
        };
        let alternatives: Vec<Vec<Char>> = if commas.is_empty() {
            let body = &word[start + 1..end];
            if body.iter().any(|c| c.quoted) {
                start += 1;
                continue;
            }
            let body: String = body.iter().map(|c| c.ch).collect();
            match sequence(&body)? {
                Some(values) => values
                    .into_iter()
                    .map(|value| value.chars().map(|ch| Char { ch, quoted: false }).collect())
                    .collect(),
                None => {
                    start += 1;
                    continue;
                }
            }
        } else {
            if commas.len() >= WORD_CAP {
                return Err(Unresolved::OverCap);
            }
            let mut bounds = vec![start];
            bounds.extend(commas);
            bounds.push(end);
            bounds.windows(2).map(|pair| word[pair[0] + 1..pair[1]].to_vec()).collect()
        };
        for alternative in alternatives {
            let mut next = word[..start].to_vec();
            next.extend(alternative);
            next.extend_from_slice(&word[end + 1..]);
            brace_expand(&next, out, level + 1)?;
        }
        return Ok(());
    }
    if out.len() >= WORD_CAP {
        return Err(Unresolved::OverCap);
    }
    out.push(word.to_vec());
    Ok(())
}

fn sequence_int(text: &str) -> Option<i128> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Bash's sequence expression. `Ok(None)`: not a sequence, braces literal. Over [`WORD_CAP`] values (or an integer too
/// large to count) is over the cap.
fn sequence(body: &str) -> Result<Option<Vec<String>>, Unresolved> {
    let parts: Vec<&str> = body.split("..").collect();
    if !(parts.len() == 2 || parts.len() == 3) {
        return Ok(None);
    }
    let is_int = |text: &str| {
        let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    };
    let step = match parts.get(2) {
        None => 1,
        Some(text) if is_int(text) => match sequence_int(text) {
            Some(step) => step.unsigned_abs().max(1) as i128,
            None => return Err(Unresolved::OverCap),
        },
        Some(_) => return Ok(None),
    };
    let count = |from: i128, to: i128| (to - from).abs() / step + 1;
    if is_int(parts[0]) && is_int(parts[1]) {
        let (Some(from), Some(to)) = (sequence_int(parts[0]), sequence_int(parts[1])) else {
            return Err(Unresolved::OverCap);
        };
        if count(from, to) > WORD_CAP as i128 {
            return Err(Unresolved::OverCap);
        }
        let padded = |text: &str| {
            let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
            digits.len() > 1 && digits.starts_with('0')
        };
        let width = if padded(parts[0]) || padded(parts[1]) { parts[0].len().max(parts[1].len()) } else { 0 };
        return Ok(Some(steps(from, to, step, |at| {
            let digits = format!("{:0>width$}", at.abs(), width = width.saturating_sub(usize::from(at < 0)));
            if at < 0 { format!("-{digits}") } else { digits }
        })));
    }
    let letter = |text: &str| {
        let mut chars = text.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) if c.is_ascii_alphabetic() => Some(c as i128),
            _ => None,
        }
    };
    if let (Some(from), Some(to)) = (letter(parts[0]), letter(parts[1])) {
        if count(from, to) > WORD_CAP as i128 {
            return Err(Unresolved::OverCap);
        }
        return Ok(Some(steps(from, to, step, |at| char::from(at as u8).to_string())));
    }
    Ok(None)
}

fn steps(from: i128, to: i128, step: i128, render: impl Fn(i128) -> String) -> Vec<String> {
    let direction = if to >= from { 1 } else { -1 };
    let mut values = Vec::new();
    let mut at = from;
    loop {
        values.push(render(at));
        let next = at + direction * step;
        if (direction > 0 && next > to) || (direction < 0 && next < to) {
            break;
        }
        at = next;
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{
        GlobMark, NormalisedWord, Unresolved, WORD_CAP, normalise_word, normalise_word_keeping_globs,
        normalise_word_marking_globs,
    };

    fn words(raw: &str) -> Vec<String> {
        match normalise_word(raw) {
            NormalisedWord::Words(words) => words,
            NormalisedWord::Unresolved(reason) => panic!("{raw:?} unresolved: {reason:?}"),
        }
    }

    fn unresolved(raw: &str) -> Unresolved {
        match normalise_word(raw) {
            NormalisedWord::Unresolved(reason) => reason,
            NormalisedWord::Words(words) => panic!("{raw:?} resolved to {words:?}"),
        }
    }

    #[test]
    fn plain_words_are_unchanged() {
        for raw in ["ls", "-la", "src/main.rs", "--color=auto", "42", "a,b", "a}b"] {
            assert_eq!(words(raw), vec![raw.to_owned()]);
        }
    }

    #[test]
    fn quotes_are_removed_and_fragments_joined() {
        assert_eq!(words("'hello world'"), vec!["hello world"]);
        assert_eq!(words("\"hello world\""), vec!["hello world"]);
        assert_eq!(words("'ec'ho"), vec!["echo"]);
        assert_eq!(words("e\"ch\"'o'"), vec!["echo"]);
        assert_eq!(words("--name='a b'"), vec!["--name=a b"]);
        assert_eq!(words("''"), vec![""]);
    }

    #[test]
    fn backslash_escapes_fold() {
        assert_eq!(words("\\ls"), vec!["ls"]);
        assert_eq!(words("l\\s"), vec!["ls"]);
        assert_eq!(words("\\;"), vec![";"]);
        assert_eq!(words("a\\ b"), vec!["a b"]);
        assert_eq!(words("\"a\\\"b\""), vec!["a\"b"]);
        // Inside double quotes only `$`, backtick, `"`, `\` and newline are escapable.
        assert_eq!(words("\"a\\nb\""), vec!["a\\nb"]);
        assert_eq!(words("'a\\b'"), vec!["a\\b"]);
        assert_eq!(words("C:\\Users\\me"), vec!["C:\\Users\\me"]);
    }

    #[test]
    fn unquoted_braces_expand() {
        assert_eq!(words("{a,b}"), vec!["a", "b"]);
        assert_eq!(words("x{a,b}y"), vec!["xay", "xby"]);
        assert_eq!(words("{a,b}{1,2}"), vec!["a1", "a2", "b1", "b2"]);
        assert_eq!(words("{a,{b,c}}"), vec!["a", "b", "c"]);
        assert_eq!(words("f{1..3}"), vec!["f1", "f2", "f3"]);
        assert_eq!(words("{01..03}"), vec!["01", "02", "03"]);
        assert_eq!(words("{c..a}"), vec!["c", "b", "a"]);
        assert_eq!(words("{1..9..4}"), vec!["1", "5", "9"]);
        assert_eq!(words("'{'a,b}"), vec!["{a,b}"]);
        assert_eq!(words("{ec'h'o,ls}"), vec!["echo", "ls"]);
    }

    #[test]
    fn braces_that_are_not_groups_stay_literal() {
        assert_eq!(words("{}"), vec!["{}"]);
        assert_eq!(words("{a}"), vec!["{a}"]);
        assert_eq!(words("{a..}"), vec!["{a..}"]);
        assert_eq!(words("{1..b}"), vec!["{1..b}"]);
        assert_eq!(words("{a"), vec!["{a"]);
    }

    #[test]
    fn quoted_braces_are_literal() {
        assert_eq!(words("'{a,b}'"), vec!["{a,b}"]);
        assert_eq!(words("\"{a,b}\""), vec!["{a,b}"]);
        assert_eq!(words("\\{a,b}"), vec!["{a,b}"]);
        assert_eq!(words("{a\\,b}"), vec!["{a,b}"]);
        assert_eq!(words("{\"1..3\"}"), vec!["{1..3}"]);
    }

    #[test]
    fn brace_expansion_over_the_cap_is_unresolved() {
        assert_eq!(words(&format!("{{1..{WORD_CAP}}}")).len(), WORD_CAP);
        assert_eq!(unresolved(&format!("{{1..{}}}", WORD_CAP + 1)), Unresolved::OverCap);
        assert_eq!(unresolved("{1..99999999999999999999}"), Unresolved::OverCap);
        assert_eq!(unresolved("{A..z}{a,b}"), Unresolved::OverCap);
        // 4 * 4 * 4 = 64 fits; one more factor does not.
        assert_eq!(words("{a,b,c,d}{a,b,c,d}{a,b,c,d}").len(), 64);
        assert_eq!(unresolved("{a,b,c,d}{a,b,c,d}{a,b,c,d}{a,b}"), Unresolved::OverCap);
    }

    /// u35 r2: nesting depth and the number of expansion steps are capped before any alternative is copied, so a deep
    /// or long brace word cannot exhaust the stack or go quadratic.
    #[test]
    fn brace_nesting_and_steps_are_capped() {
        let nest = |depth: usize| format!("{}a{}", "{".repeat(depth), ",b}".repeat(depth));
        assert_eq!(words(&nest(super::BRACE_DEPTH_CAP)).len(), super::BRACE_DEPTH_CAP + 1);
        assert_eq!(unresolved(&nest(super::BRACE_DEPTH_CAP + 1)), Unresolved::OverCap);
        assert_eq!(unresolved(&nest(5000)), Unresolved::OverCap);
        // Many sibling groups of one alternative each never reach the word cap, only the step cap.
        assert_eq!(unresolved(&"{1..1}".repeat(5000)), Unresolved::OverCap);
        assert_eq!(unresolved(&format!("{{{}}}", vec!["a"; 5000].join(","))), Unresolved::OverCap);
    }

    #[test]
    fn unquoted_globs_are_unresolved() {
        assert_eq!(unresolved("*.rs"), Unresolved::Glob);
        assert_eq!(unresolved("file?.txt"), Unresolved::Glob);
        assert_eq!(unresolved("[ab].txt"), Unresolved::Glob);
        assert_eq!(unresolved("{a,*}"), Unresolved::Glob);
        assert_eq!(words("'*.rs'"), vec!["*.rs"]);
        assert_eq!(words("\\*"), vec!["*"]);
        assert_eq!(words("\"a?b\""), vec!["a?b"]);
        // A `[` with no closing `]` cannot match anything but itself.
        assert_eq!(words("["), vec!["["]);
        assert_eq!(words("]"), vec!["]"]);
    }

    #[test]
    fn keeping_globs_returns_the_pattern() {
        let keep = |raw| normalise_word_keeping_globs(raw);
        assert_eq!(keep("src/*.rs"), NormalisedWord::Words(vec!["src/*.rs".to_owned()]));
        assert_eq!(keep("'s'rc/{a,b}*"), NormalisedWord::Words(vec!["src/a*".to_owned(), "src/b*".to_owned()]));
        assert_eq!(keep("$X*"), NormalisedWord::Unresolved(Unresolved::Expansion));
        assert_eq!(keep("{1..99999}"), NormalisedWord::Unresolved(Unresolved::OverCap));
    }

    #[test]
    fn expansions_and_malformed_words_are_unresolved() {
        assert_eq!(unresolved("$HOME"), Unresolved::Expansion);
        assert_eq!(unresolved("\"$HOME/x\""), Unresolved::Expansion);
        assert_eq!(unresolved("a$(id)"), Unresolved::Expansion);
        assert_eq!(unresolved("`id`"), Unresolved::Expansion);
        assert_eq!(unresolved("$'a'"), Unresolved::Expansion);
        assert_eq!(unresolved("'abc"), Unresolved::Malformed);
        assert_eq!(unresolved("\"abc"), Unresolved::Malformed);
        assert_eq!(unresolved("abc\\"), Unresolved::Malformed);
        assert_eq!(unresolved("{a,}"), Unresolved::Malformed);
        assert_eq!(words("'$HOME'"), vec!["$HOME"]);
        assert_eq!(words("\\$HOME"), vec!["$HOME"]);
    }

    fn marks(raw: &str) -> Vec<GlobMark> {
        normalise_word_marking_globs(raw).unwrap().into_iter().map(|w| w.glob).collect()
    }

    #[test]
    fn glob_marks_tell_anchored_from_option_capable() {
        use GlobMark::{Anchored, Literal, OptionCapable};
        for raw in ["src/*.rs", "./*.md", "feat*", "a[bc]", "~/x*", "'*'x*"] {
            assert_eq!(marks(raw), vec![Anchored], "{raw}");
        }
        for raw in ["*", "*.rs", "?ompress", "[ab]c", "-*", "'-'*", "\\-x?"] {
            assert_eq!(marks(raw), vec![OptionCapable], "{raw}");
        }
        for raw in ["'*'", "\\*", "\"a?b\"", "[", "ls"] {
            assert_eq!(marks(raw), vec![Literal], "{raw}");
        }
        assert_eq!(marks("{src/*,*}"), vec![Anchored, OptionCapable]);
    }
}
