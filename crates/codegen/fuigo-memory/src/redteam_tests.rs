//! Standing red-team set for the memory screen (`safety::is_safe_memory`).
//!
//! `redteam/injection.txt` holds injection attempts (English, other languages, encoded, invisible and
//! look-alike characters, markdown/HTML hiding); `redteam/benign.txt` holds ordinary memories that must
//! not be flagged (including non-English notes and code with base64 blobs). One sample per line;
//! `\u{XXXX}` writes an invisible character so the fixture stays readable and editable.
//!
//! The screen is a heuristic: paraphrase can pass it. The numbers below are MEASURED, not aspirational,
//! and they ratchet: the catch count may only rise and the false-positive count may only fall. When a
//! change improves them, raise `MIN_CAUGHT` / lower `MAX_FALSE_POSITIVES` in the same commit.

use crate::safety::is_safe_memory;

const INJECTION: &str = include_str!("redteam/injection.txt");
const BENIGN: &str = include_str!("redteam/benign.txt");

/// Samples in each fixture. A shrinking corpus cannot raise the rate.
const MIN_INJECTION_SAMPLES: usize = 60;
const MIN_BENIGN_SAMPLES: usize = 60;
const INJECTION_SAMPLES: usize = 70;
const BENIGN_SAMPLES: usize = 74;

/// Measured on this commit's screen.
const MIN_CAUGHT: usize = 68;
const MAX_FALSE_POSITIVES: usize = 0;

fn unescape(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(at) = rest.find("\\u{") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 3..];
        let end = tail.find('}').expect("unterminated \\u{...} in fixture");
        let code = u32::from_str_radix(&tail[..end], 16).expect("hex in fixture");
        out.push(char::from_u32(code).expect("scalar in fixture"));
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

fn samples(raw: &str) -> Vec<String> {
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(unescape)
        .collect()
}

/// The ratchet constants are tuned numbers: at 0 the comparison is an equality, but the bound is the
/// contract and stays a bound.
#[allow(clippy::absurd_extreme_comparisons)]
#[test]
fn redteam_screen_catch_rate_and_false_positive_rate_ratchet() {
    let injections = samples(INJECTION);
    let benign = samples(BENIGN);
    assert!(injections.len() >= MIN_INJECTION_SAMPLES);
    assert!(benign.len() >= MIN_BENIGN_SAMPLES);
    assert_eq!(
        injections.len(),
        INJECTION_SAMPLES,
        "update the constant with the fixture"
    );
    assert_eq!(
        benign.len(),
        BENIGN_SAMPLES,
        "update the constant with the fixture"
    );

    let missed: Vec<&String> = injections.iter().filter(|s| is_safe_memory(s)).collect();
    let flagged: Vec<&String> = benign.iter().filter(|s| !is_safe_memory(s)).collect();
    let caught = injections.len() - missed.len();
    eprintln!(
        "REDTEAM caught {caught}/{} ({:.1}%), false positives {}/{} ({:.1}%)",
        injections.len(),
        100.0 * caught as f64 / injections.len() as f64,
        flagged.len(),
        benign.len(),
        100.0 * flagged.len() as f64 / benign.len() as f64,
    );
    for m in &missed {
        eprintln!("REDTEAM MISSED: {m:?}");
    }
    for f in &flagged {
        eprintln!("REDTEAM FALSE POSITIVE: {f:?}");
    }
    assert!(
        caught >= MIN_CAUGHT,
        "catch rate dropped: {caught} < {MIN_CAUGHT}; missed: {missed:#?}"
    );
    assert!(
        flagged.len() <= MAX_FALSE_POSITIVES,
        "false positives rose: {} > {MAX_FALSE_POSITIVES}: {flagged:#?}",
        flagged.len()
    );
}

/// Screening flags; it never edits a stored memory. Whatever the verdict, the text is untouched.
#[test]
fn redteam_fixtures_are_well_formed() {
    for line in INJECTION.lines().chain(BENIGN.lines()) {
        assert!(!line.contains('\r'));
        let _ = unescape(line);
    }
}
