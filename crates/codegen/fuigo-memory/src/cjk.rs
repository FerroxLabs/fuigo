//! Full-text search over scripts that do not put spaces between words.
//!
//! FTS5's default tokenizer reads a run of Han, kana or Hangul characters as ONE token, so a note that says
//! "我们讨论了数据库迁移" could only be found by that whole sentence. Both sides are therefore segmented the same way:
//! every such character is indexed as its own token (the text gets a space around it). A query run of one or two characters
//! becomes a phrase of those tokens, which matches wherever it occurs inside a sentence; a longer run becomes the set of
//! its adjacent character pairs, any of which may match, so "迁移方案" still finds "迁移的方案" and the note holding more of the
//! pairs scores higher.
//!
//! Text without such characters is returned unchanged, so an index of Latin text is byte-for-byte what it was.

use std::borrow::Cow;

/// Bump when the segmentation changes: [`crate::index::MemoryIndex`] rebuilds the keyword index when the stored value differs.
pub(crate) const FTS_SEGMENTATION_VERSION: &str = "1";

/// Han ideographs, kana, Hangul syllables and the CJK punctuation-free blocks around them.
pub(crate) fn is_cjk(c: char) -> bool {
    matches!(u32::from(c),
        0x3040..=0x30FF       // hiragana, katakana
        | 0x31F0..=0x31FF     // katakana phonetic extensions
        | 0x3400..=0x4DBF     // CJK extension A
        | 0x4E00..=0x9FFF     // CJK unified ideographs
        | 0xAC00..=0xD7AF     // Hangul syllables
        | 0xF900..=0xFAFF     // compatibility ideographs
        | 0xFF66..=0xFF9F     // half-width katakana
        | 0x20000..=0x2FA1F   // extensions B to F, compatibility supplement
    )
}

pub(crate) fn contains_cjk(text: &str) -> bool {
    text.chars().any(is_cjk)
}

/// The text as the keyword index stores it: a space around every CJK character.
pub(crate) fn fts_text(text: &str) -> Cow<'_, str> {
    if !contains_cjk(text) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() * 2);
    for c in text.chars() {
        if is_cjk(c) {
            out.push(' ');
            out.push(c);
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// The adjacent character pairs of a run (the run itself when it is one or two characters).
fn grams(run: &str) -> Vec<String> {
    let chars: Vec<char> = run.chars().collect();
    if chars.len() <= 2 {
        return vec![run.to_owned()];
    }
    chars.windows(2).map(|w| w.iter().collect()).collect()
}

fn phrase(gram: &str) -> String {
    let spaced: Vec<String> = gram.chars().map(String::from).collect();
    format!("\"{}\"", spaced.join(" "))
}

fn cjk_run_expr(run: &str) -> String {
    let phrases: Vec<String> = grams(run).iter().map(|g| phrase(g)).collect();
    if phrases.len() == 1 { phrases.into_iter().next().unwrap_or_default() } else { format!("({})", phrases.join(" OR ")) }
}

/// One keyword as an FTS5 expression: a bare word for Latin text, a quoted phrase of single characters for each CJK run.
fn keyword_expr(keyword: &str) -> String {
    if !contains_cjk(keyword) {
        return keyword.to_owned();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut run = String::new();
    let mut run_is_cjk = false;
    fn flush(run: &mut String, run_is_cjk: bool, parts: &mut Vec<String>) {
        if run.is_empty() {
            return;
        }
        if run_is_cjk {
            parts.push(cjk_run_expr(run));
        } else {
            parts.push(run.clone());
        }
        run.clear();
    }
    for c in keyword.chars() {
        if is_cjk(c) != run_is_cjk {
            flush(&mut run, run_is_cjk, &mut parts);
            run_is_cjk = is_cjk(c);
        }
        run.push(c);
    }
    flush(&mut run, run_is_cjk, &mut parts);
    if parts.len() > 1 { format!("({})", parts.join(" ")) } else { parts.remove(0) }
}

/// The `MATCH` expression for a set of keywords: any one of them is enough, as before.
pub(crate) fn match_expression(keywords: &[String]) -> String {
    keywords.iter().map(|k| keyword_expr(k)).collect::<Vec<_>>().join(" OR ")
}

/// How much of a CJK `keyword` a (lowercased) chunk holds, from 0 to 1: the share of its character pairs found in the text.
/// A keyword without CJK characters scores 0 here; the caller judges those by whole tokens.
pub(crate) fn cjk_keyword_coverage(lowered_chunk: &str, keyword: &str) -> f64 {
    if !contains_cjk(keyword) {
        return 0.0;
    }
    let mut total = 0usize;
    let mut found = 0usize;
    let mut run = String::new();
    let count = |run: &mut String, total: &mut usize, found: &mut usize| {
        if run.is_empty() {
            return;
        }
        for gram in grams(run) {
            *total += 1;
            if lowered_chunk.contains(&gram) {
                *found += 1;
            }
        }
        run.clear();
    };
    for c in keyword.chars() {
        if is_cjk(c) {
            run.push(c);
        } else {
            count(&mut run, &mut total, &mut found);
        }
    }
    count(&mut run, &mut total, &mut found);
    if total == 0 { 0.0 } else { found as f64 / total as f64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_without_cjk_is_untouched() {
        assert!(matches!(fts_text("plain ascii text, ünïcode too"), Cow::Borrowed(_)));
    }

    #[test]
    fn every_cjk_character_becomes_its_own_token() {
        assert_eq!(fts_text("a数据b").split_whitespace().collect::<Vec<_>>(), ["a", "数", "据", "b"]);
    }

    #[test]
    fn expressions_quote_cjk_runs_and_leave_latin_words_bare() {
        let k = |s: &str| s.to_owned();
        assert_eq!(match_expression(&[k("migration")]), "migration");
        assert_eq!(match_expression(&[k("数据")]), "\"数 据\"");
        assert_eq!(match_expression(&[k("数据库")]), "(\"数 据\" OR \"据 库\")");
        assert_eq!(match_expression(&[k("v2数据"), k("plan")]), "(v2 \"数 据\") OR plan");
    }

    #[test]
    fn coverage_is_the_share_of_character_pairs_present() {
        assert_eq!(cjk_keyword_coverage("我们讨论了数据库迁移", "数据库"), 1.0);
        assert_eq!(cjk_keyword_coverage("迁移的方案", "迁移方案"), 2.0 / 3.0);
        assert_eq!(cjk_keyword_coverage("nothing here", "数据库"), 0.0);
        assert_eq!(cjk_keyword_coverage("数据库", "database"), 0.0);
    }
}
