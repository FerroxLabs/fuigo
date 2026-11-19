use regex::{Regex, RegexSet};
use std::borrow::Cow;
use std::sync::LazyLock;

const REDACTED: &str = "[REDACTED_SECRET]";
const REDACTED_URL_VALUE: &str = "redacted";

/// Vendor API keys with `sk-`/`sk_` prefixes and Ferrox Labs (`fuigo-`) keys.
/// The `\b` anchor keeps the `sk-` inside `task-`/`disk-`/`risk-` from matching.
static API_KEY_PREFIX_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b(?:sk[-_]|fuigo-)[A-Za-z0-9_-]{20,}"));
/// AWS long-term (`AKIA`) and temporary (`ASIA`) access-key IDs.
static AWS_ACCESS_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"));
/// GitHub PATs: classic (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`) and fine-grained (`github_pat_`).
static GITHUB_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"));
/// GitLab (`glpat-`) and Slack (`xoxa-`/`xoxb-`/`xoxp-`/`xapp-`) tokens.
static VENDOR_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\b(?:glpat-|xox[abprs]-|xapp-)[A-Za-z0-9-]{10,}"));
/// Other vendor token families with a fixed prefix (audit S11-F2): npm, Hugging Face, SendGrid, DigitalOcean, Shopify,
/// Stripe live publishable/restricted keys and webhook secrets, Groq, PyPI and Google OAuth access tokens. (Stripe
/// `sk_live_` is already covered by the `sk_` prefix pattern.) Every alternative starts with a literal, so the scan
/// stays linear.
static OTHER_VENDOR_TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"\b(?:npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|do[por]_v1_[a-f0-9]{40,}|shp(?:at|ss|ca|pa)_[a-f0-9]{32}|(?:whsec|pk_live|rk_live)_[A-Za-z0-9]{20,}|gsk_[A-Za-z0-9]{30,}|pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{10,}|ya29\.[A-Za-z0-9_-]{20,})",
    )
});
/// An HTTP `Basic` credential, only after an `Authorization` header name (a bare "Basic <word>" is ordinary prose).
/// The header name and scheme are kept in the replacement.
static BASIC_AUTH_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(r#"(?i)\b(authorization["']?\s*[:=]\s*["']?basic)\s+([A-Za-z0-9+/=]{8,})"#)
});
/// Google API keys (`AIza` + 35 chars).
static GOOGLE_API_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\bAIza[0-9A-Za-z_-]{35}"));
/// PEM private-key block (any key type), base64 body included.
/// The `(?s)` flag lets `.` span the newline-delimited body.
static PEM_PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
});
/// One ANSI escape sequence (CSI: colour, cursor and erase codes), as a regex fragment. A torn key that was printed to
/// a terminal carries these between and after its lines (P120, R113 r5 #3).
const ANSI_ESCAPE: &str = r"\x1b\[[0-9;?]*[ -/]*[@-~]";

/// A PEM private-key block with no END line (P113 r3, Astra r3 #6: a torn file, or output cut short): the BEGIN line
/// and, when nothing but blanks and colour codes follow the marker on its line, every following line that is wholly
/// base64 (indented or not, Astra r4 #4, with colour codes around it, P120; a line with any other text ends the body
/// and is kept, Astra r4 #6). A marker with ordinary text after it on its line is redacted along with that line and
/// opens no body (P120, Astra r5 #4). Runs after [`PEM_PRIVATE_KEY_REGEX`], so it only meets a block that has no end.
/// Archive only ([`redact_credential_shapes`]): the telemetry scrub keeps an unterminated BEGIN line so Sentry's
/// fragment check, which joins scrubbed strings, still sees the whole block (Astra r4 #2).
static PEM_UNTERMINATED_PRIVATE_KEY_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r"(?m)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:(?:{ansi}|[ \t])*\r?$(?:\r?\n[ \t]*(?:{ansi})*[A-Za-z0-9+/=]+(?:{ansi}|[ \t])*\r?$)*|[^\n]*)",
        ansi = ANSI_ESCAPE
    ))
});
/// The marker alone, for [`opens_private_key_block`].
static PEM_BEGIN_MARKER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"));
/// Colour and cursor codes, removed before a string is judged to be key body.
static ANSI_ESCAPE_REGEX: LazyLock<Regex> = LazyLock::new(|| compile(ANSI_ESCAPE));
static BEARER_TOKEN_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{16,}\b"));
/// Bare JWT (`eyJ...header.payload.signature`) with no `Bearer`/`sk-` prefix, the shape used by deployment keys and OIDC tokens.
static JWT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"));
/// 8-char value floor to avoid false positives on short values. The keyword may follow an identifier prefix
/// (`GITHUB_TOKEN`, `DB_PASSWORD`) and may be closed by a quote before the separator (`"password": "..."`), audit
/// S11-F2. The keyword must still end the name (`tokens`, `token_count` do not match). The prefix is capped at 64
/// characters and has no `\b` anchor: an unbounded prefix lets the engine's reverse scan from each keyword hit walk
/// back over the whole identifier run, which is quadratic on a long run holding many keywords.
static SECRET_ASSIGNMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?ix)
        (
            [a-z0-9_]{0,64}(?:
                api[_-]?key
              | (?:access|refresh|id)[_-]token
              | token
              | secret(?:[_-](?:access[_-])?key)?
              | client[_-]secret
              | password
            )
        )
        (["']?)
        (\s*[:=]\s*)
        (["']?)
        ([^\s"',&]{8,})
        "#,
    )
});

/// Whether the value of a secret-looking assignment is plainly not a secret (review M1): wholly a variable reference
/// (`$TOKEN`, `${TOKEN}`, `${{secrets.TOKEN}}`, a closed `$(...)`, a complete shell parameter expansion such as
/// `${TOKEN:-fallback}`), a closed placeholder (`<your-token>`), or code, meaning an identifier made of letters with a
/// structural character (`. : < ( [`) and no digit (`resp.next_page_token`, `Option<String>`, `generate_csrf_token(`;
/// never for a quoted literal), or an ellipsis placeholder (`eyJhbGciOi...`). A value that merely starts like a
/// reference or placeholder (`$ecureP@ss`, a `$apr1$` hash, `<abc`), a plain word, words joined by `_`, a mixed-case
/// or digit-bearing string, or anything else redacts.
/// Delta review D2-05: `name` is the assignment's name. A password is never shown cut short, so after a password name
/// an ellipsis is part of the literal; and code whose only structural characters are `.` and `:` must name a
/// credential somewhere (`config.password`, `resp.next_page_token`), so words joined by dots
/// (`correct.horse.battery.staple`) are a literal too.
fn assignment_value_is_benign(name: &str, value: &str, quoted: bool) -> bool {
    let value = value.trim_end_matches(';');
    let password_name = name.to_ascii_lowercase().ends_with("password");
    if (value.ends_with("...") || value.ends_with('\u{2026}')) && !password_name {
        return true;
    }
    let is_name = |name: &str| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some(reference) = value.strip_prefix('$') {
        let braced = reference
            .strip_prefix('{')
            .and_then(|r| r.strip_suffix('}'))
            .is_some_and(|inner| {
                (!inner.is_empty()
                    && inner
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.{}".contains(c)))
                    || is_shell_parameter_expansion(inner)
            });
        let command = reference.starts_with('(') && reference.ends_with(')') && reference.len() > 2;
        return is_name(reference) || braced || command;
    }
    if value.starts_with('<') {
        return value.len() > 2 && value.ends_with('>');
    }
    let code = !quoted
        && value.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_alphabetic() || "_.:<>()[]*;".contains(c))
        && value.chars().any(|c| ".:<([".contains(c));
    let only_dots_and_colons = !value.chars().any(|c| "<>()[]*".contains(c));
    code && (!only_dots_and_colons || names_a_credential(value))
}

/// Whether `inner` (the text between `${` and `}`) is a complete shell parameter expansion: an optional `#` or `!`,
/// a variable name, then nothing or an operator (`:-` `-` `:=` `=` `:?` `?` `:+` `+` `#` `##` `%` `%%` `/` `//` `:`)
/// followed by any text without braces (delta review D2-05: `${TOKEN:-fallback}` is a reference, not a secret).
fn is_shell_parameter_expansion(inner: &str) -> bool {
    let inner = inner.strip_prefix(['#', '!']).unwrap_or(inner);
    let name_len = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    let (name, operator) = inner.split_at(name_len);
    let valid_name = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || (!name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()));
    valid_name
        && !operator.contains(['{', '}'])
        && (operator.is_empty() || operator.starts_with([':', '-', '=', '?', '+', '#', '%', '/']))
}

/// Whether code such as `config.password` or `resp.next_page_token` names a credential in one of its parts: a whole
/// part (split on `.`, `:` and `_`), so `monkey.business` and `author.name` are not read as naming one.
fn names_a_credential(value: &str) -> bool {
    const WORDS: [&str; 9] = [
        "token",
        "key",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "cred",
        "credentials",
    ];
    let value = value.to_ascii_lowercase();
    value
        .split(['.', ':', '_'])
        .any(|part| WORDS.contains(&part))
}

static SENSITIVE_QUERY_PARAMS: &[&str] = &[
    "access_token",
    "api_key",
    "assertion",
    "auth",
    "client_secret",
    "code",
    "code_verifier",
    "id_token",
    "key",
    "password",
    "refresh_token",
    "requested_token",
    "session_id",
    "state",
    "subject_token",
    "token",
];

/// Excludes trailing punctuation so backticks/brackets in surrounding text don't get folded into the URL match.
static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| compile(r#"https?://[^\s"'<>(){}\[\],;`]+"#));

static MATCH_ANY: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        API_KEY_PREFIX_REGEX.as_str(),
        AWS_ACCESS_KEY_REGEX.as_str(),
        GITHUB_TOKEN_REGEX.as_str(),
        VENDOR_TOKEN_REGEX.as_str(),
        OTHER_VENDOR_TOKEN_REGEX.as_str(),
        BASIC_AUTH_REGEX.as_str(),
        GOOGLE_API_KEY_REGEX.as_str(),
        PEM_PRIVATE_KEY_REGEX.as_str(),
        PEM_UNTERMINATED_PRIVATE_KEY_REGEX.as_str(),
        BEARER_TOKEN_REGEX.as_str(),
        JWT_REGEX.as_str(),
        URL_REGEX.as_str(),
        SECRET_ASSIGNMENT_REGEX.as_str(),
    ])
    .expect("redact_secrets RegexSet")
});

/// Telemetry scrub: credentials this process sent upstream (exact match, [`crate::sent_credentials`]), then the
/// secret-shape patterns. The exact-match pass runs first so a recorded credential is replaced whole before a shape
/// pattern can rewrite part of it.
pub fn redact_secrets(input: &str) -> Cow<'_, str> {
    match crate::sent_credentials::scrub(input) {
        Cow::Borrowed(input) => redact_secret_shapes(input),
        Cow::Owned(scrubbed) => Cow::Owned(redact_secret_shapes(&scrubbed).into_owned()),
    }
}

fn redact_secret_shapes(input: &str) -> Cow<'_, str> {
    redact_shapes(input, true)
}

/// Whether `input` opens a PEM private-key block it does not close: its last BEGIN marker has no END after it, nothing
/// but blanks and colour codes follows the marker on its line, and every line after that is base64 (or blank). The body
/// may then follow in the next string or record ([`PrivateKeyJoin`]). A marker with ordinary text after it, on its
/// line or on a line after the body, opens nothing (P113 r4 #1; P120, Astra r5 #4).
pub fn opens_private_key_block(input: &str) -> bool {
    let rest = PEM_PRIVATE_KEY_REGEX.replace_all(input, "");
    let Some(marker) = PEM_BEGIN_MARKER_REGEX.find_iter(&rest).last() else {
        return false;
    };
    let mut lines = rest[marker.end()..].split('\n');
    let blank = |line: &str| ANSI_ESCAPE_REGEX.replace_all(line, "").trim().is_empty();
    lines.next().is_some_and(blank) && lines.all(|line| blank(line) || is_key_body(line))
}

/// Whether `text` is key body: every line, once colour codes and surrounding whitespace are removed, is blank or one
/// unbroken base64 token (a PEM line holds no spaces), and at least one line is not blank.
fn is_key_body(text: &str) -> bool {
    let mut any = false;
    for line in text.split('\n') {
        let plain = ANSI_ESCAPE_REGEX.replace_all(line, "");
        let plain = plain.trim();
        if plain.is_empty() {
            continue;
        }
        if !plain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
        {
            return false;
        }
        any = true;
    }
    any
}

/// A private key whose text is split over several strings, of one record or of consecutive records (P113 r4 #1; P120,
/// R113 r5 #1/#4, K16): the strings are fed in document order, each with the name of the property that holds it.
///
/// After a string that opens a block ([`opens_private_key_block`]):
/// - a string that holds the END marker is replaced through it and closes the block;
/// - a string that is key body (see [`is_key_body`]) and at least 16 characters is replaced whole, whatever property
///   holds it (a key may be spread over `a`, `b`, `c` of one record);
/// - a SHORT string of the same property that is body and has a digit, `+`, `/` or `=` in it is a chunk of a key
///   streamed in small pieces and is replaced too; a short word of letters only is not (it is prose);
/// - any other string of the SAME property (ordinary text) ends the block and is left to the ordinary scrub;
/// - any other string of ANOTHER property is the record envelope (`method`, `sessionId`, `type`, ...) between two
///   chunks: it is kept and neither continues nor ends the block.
///
/// A BEGIN marker that is itself split across two strings of one property (`-----BEGIN PRI` + `VATE KEY-----`) opens
/// the block when the second string completes it.
#[derive(Debug, Default)]
pub struct PrivateKeyJoin {
    /// The property of the string that opened the block (`Some(None)`: a string with no property), `None` when closed.
    open: Option<Option<String>>,
    /// Key material has been seen since the block opened: from then on any base64 token of the opening property, of any
    /// length, is body.
    body_seen: bool,
    /// The tail of the last strings, when it is the start of a BEGIN marker, with its property.
    partial: Option<(Option<String>, String)>,
}

impl PrivateKeyJoin {
    /// Whether a block is open.
    pub fn is_open(&self) -> bool {
        self.open.is_some()
    }

    /// Forget an open block (a record that is not JSON ends the run of strings).
    pub fn reset(&mut self) {
        self.open = None;
        self.body_seen = false;
        self.partial = None;
    }

    /// Feed the next string. Redacts the parts of `s` that belong to a key opened earlier (and notes whether `s` opens
    /// one); returns `true` when `s` changed. Call [`redact_credential_shapes`] on what is left afterwards: this
    /// leaves a BEGIN marker in place for it.
    pub fn feed(&mut self, property: Option<&str>, s: &mut String) -> bool {
        let mut changed = false;
        // A fragment of another property is the record envelope in between: it stays until its own property comes.
        let (fragment, kept) = match self.partial.take() {
            Some((owner, fragment)) if owner.as_deref() == property => (Some(fragment), None),
            other => (None, other),
        };
        // The marker may be split over more than two strings: the next fragment extends this one.
        let next_partial = fragment
            .as_ref()
            .and_then(|fragment| marker_fragment(&format!("{fragment}{s}")))
            .or_else(|| marker_fragment(s))
            .map(|fragment| (property.map(str::to_owned), fragment));
        let mut opened = false;
        if let Some(owner) = self.open.clone() {
            let same = owner.as_deref() == property;
            let plain = ANSI_ESCAPE_REGEX.replace_all(s, "").into_owned();
            if let Some(end) = end_marker_end(s) {
                let rest = s.split_off(end);
                *s = format!("{REDACTED}{rest}");
                self.open = None;
                self.body_seen = false;
                changed = true;
            } else if is_key_body(s)
                && (body_chars(s) >= 16
                    || self.body_seen
                    || starts_like_key(plain.trim())
                    || (same && has_base64_marker(&plain)))
            {
                *s = REDACTED.to_string();
                self.body_seen = true;
                return true;
            } else if plain.trim().is_empty() {
                return false;
            } else if !same && !plain.trim().contains(char::is_whitespace) {
                // The record envelope between two chunks: kept, neither continues nor ends the block.
                return false;
            } else {
                // Ordinary text (of any property) ends the block; body lines before it go, the text stays.
                self.open = None;
                self.body_seen = false;
                changed = redact_leading_key_body(s);
            }
        } else if let Some(fragment) = fragment {
            let joined = format!("{fragment}{s}");
            opened = opens_private_key_block(&joined);
            let redacted = redact_private_key_blocks(&joined);
            if redacted != joined.as_str() {
                *s = redacted.into_owned();
                changed = true;
            }
        }
        if opened || opens_private_key_block(s) {
            self.open = Some(property.map(str::to_owned));
            self.body_seen = false;
            self.partial = None;
        } else {
            self.partial = next_partial.or(kept);
        }
        changed
    }
}

/// Whether `text` begins like the base64 of a DER or OpenSSH private key (`MIIE`, `MIGH`, `MHcC`, `b3Bl`), or is the
/// first letters of one (a key streamed one letter at a time starts with `M`). A word such as `MISSING` does not.
fn starts_like_key(text: &str) -> bool {
    const STARTS: [&str; 6] = ["MIIE", "MIIB", "MIGH", "MHcC", "MHgC", "b3Bl"];
    !text.is_empty()
        && STARTS.iter().any(|start| {
            start.starts_with(text) || (text.len() > start.len() && text.starts_with(start))
        })
}

/// The number of base64 characters of `text` (colour codes and whitespace not counted).
fn body_chars(text: &str) -> usize {
    ANSI_ESCAPE_REGEX
        .replace_all(text, "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .count()
}

/// Whether `text` has a digit, `+`, `/` or `=`: a short run of those is key material, not a word.
fn has_base64_marker(text: &str) -> bool {
    ANSI_ESCAPE_REGEX
        .replace_all(text, "")
        .chars()
        .any(|c| c.is_ascii_digit() || "+/=".contains(c))
}

/// When `s` ends with the START of a BEGIN marker (`-----BEGIN PRI`), that tail.
fn marker_fragment(s: &str) -> Option<String> {
    let Some(at) = s.rfind("-----") else {
        // The first dashes of the marker alone (`---` + `--BEGIN `).
        let dashes = s.len() - s.trim_end_matches('-').len();
        return (1..5)
            .contains(&dashes)
            .then(|| s[s.len() - dashes..].to_string());
    };
    let tail = &s[at..];
    let rest = &tail["-----".len()..];
    let plausible = tail.len() <= 64
        && !tail.contains('\n')
        && ("BEGIN".starts_with(rest)
            || rest.strip_prefix("BEGIN ").is_some_and(|words| {
                !words.contains("PRIVATE KEY-----")
                    && words
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c == ' ' || c == '-')
            }));
    plausible.then(|| tail.to_string())
}

/// The end of the first END marker of a private key in `s`, as a byte offset.
fn end_marker_end(s: &str) -> Option<usize> {
    const TAIL: &str = "PRIVATE KEY-----";
    let at = s.find("-----END ")?;
    let tail = s[at..].find(TAIL)?;
    Some(at + tail + TAIL.len())
}

/// Replace the leading lines of `s` that are base64 by [`REDACTED`]; `true` when there were any.
fn redact_leading_key_body(s: &mut String) -> bool {
    let mut end = 0;
    for line in s.split_inclusive('\n') {
        if !(is_key_body(line) && (body_chars(line) >= 16 || has_base64_marker(line))) {
            break;
        }
        end += line.len();
    }
    if end == 0 {
        return false;
    }
    let newline = if s[..end].ends_with('\n') { "\n" } else { "" };
    *s = format!("{REDACTED}{newline}{}", &s[end..]);
    true
}

/// The secret-shape patterns of [`redact_secrets`] (vendor and Fuigo key prefixes, AWS, GitHub, GitLab/Slack, Google,
/// PEM private keys, `Bearer`, bare JWTs, `secret=value` assignments), WITHOUT the exact-match pass and WITHOUT
/// rewriting URLs: each match is replaced and every other byte of `input` is kept as it was (a URL is not re-serialised,
/// so text that is not a credential is never normalised). For a sink that must catch a credential this process never
/// recorded, e.g. an old key echoed into a session file (P113).
pub fn redact_credential_shapes(input: &str) -> Cow<'_, str> {
    redact_shapes(input, false)
}

/// Only the PEM private-key blocks of [`redact_credential_shapes`] (a complete block, then one with no END line from
/// its BEGIN line through its base64 body), matched across lines: for plain-text lines that are scrubbed one at a time
/// afterwards, where a block's BEGIN and END lines are apart.
pub fn redact_private_key_blocks(input: &str) -> Cow<'_, str> {
    match PEM_PRIVATE_KEY_REGEX.replace_all(input, REDACTED) {
        Cow::Borrowed(input) => PEM_UNTERMINATED_PRIVATE_KEY_REGEX.replace_all(input, REDACTED),
        Cow::Owned(s) => Cow::Owned(
            PEM_UNTERMINATED_PRIVATE_KEY_REGEX
                .replace_all(&s, REDACTED)
                .into_owned(),
        ),
    }
}

/// `telemetry`: the [`redact_secrets`] flavour (URLs re-serialised with sensitive parameters redacted; only complete
/// PEM blocks). Otherwise the [`redact_credential_shapes`] flavour (URLs untouched; torn PEM blocks too).
fn redact_shapes(input: &str, telemetry: bool) -> Cow<'_, str> {
    if !MATCH_ANY.is_match(input) {
        return Cow::Borrowed(input);
    }
    let s = if telemetry {
        PEM_PRIVATE_KEY_REGEX.replace_all(input, REDACTED)
    } else {
        redact_private_key_blocks(input)
    };
    let s = API_KEY_PREFIX_REGEX.replace_all(&s, REDACTED);
    let s = AWS_ACCESS_KEY_REGEX.replace_all(&s, REDACTED);
    let s = GITHUB_TOKEN_REGEX.replace_all(&s, REDACTED);
    let s = VENDOR_TOKEN_REGEX.replace_all(&s, REDACTED);
    let s = OTHER_VENDOR_TOKEN_REGEX.replace_all(&s, REDACTED);
    // A plain lower-case word after `Authorization: Basic` is prose (review S11-F2-R1); anything else (a digit, an
    // upper-case letter, one of `+ / =`) is taken for base64 of `user:password`, letters-only credentials included.
    let s = BASIC_AUTH_REGEX.replace_all(&s, |c: &regex::Captures<'_>| {
        if !c[2].chars().all(|ch| ch.is_ascii_lowercase()) {
            format!("{} {REDACTED}", &c[1])
        } else {
            c[0].to_owned()
        }
    });
    let s = GOOGLE_API_KEY_REGEX.replace_all(&s, REDACTED);
    let s = BEARER_TOKEN_REGEX.replace_all(&s, format!("Bearer {REDACTED}"));
    let s = JWT_REGEX.replace_all(&s, REDACTED);
    let s = if telemetry {
        Cow::Owned(redact_urls_in(&s))
    } else {
        s
    };
    let s = SECRET_ASSIGNMENT_REGEX
        .replace_all(&s, |c: &regex::Captures<'_>| {
            if assignment_value_is_benign(&c[1], &c[5], !c[4].is_empty()) {
                c[0].to_owned()
            } else {
                format!("{}{}{}{}{REDACTED}", &c[1], &c[2], &c[3], &c[4])
            }
        })
        .into_owned();
    // A URL or a near miss can trip `MATCH_ANY` without any pattern replacing anything: report "unchanged" then.
    if s == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(s)
    }
}

/// Use [`redact_json_string_values`] for the standard scrub; use this directly only when composing a custom one.
pub fn walk_json_strings(value: &mut serde_json::Value, f: &mut impl FnMut(&mut String)) {
    match value {
        serde_json::Value::String(s) => f(s),
        serde_json::Value::Array(arr) => arr.iter_mut().for_each(|v| walk_json_strings(v, f)),
        serde_json::Value::Object(map) => map.values_mut().for_each(|v| walk_json_strings(v, f)),
        _ => {}
    }
}

pub fn redact_json_string_values(value: &mut serde_json::Value) {
    walk_json_strings(value, &mut |s| {
        if let Cow::Owned(replaced) = redact_secrets(s) {
            *s = replaced;
        }
    });
}

fn redact_urls_in(text: &str) -> String {
    URL_REGEX
        .replace_all(text, |caps: &regex::Captures<'_>| {
            let raw = &caps[0];
            url::Url::parse(raw).map_or_else(
                |_| raw.to_owned(),
                |mut url| {
                    redact_url(&mut url);
                    url.to_string()
                },
            )
        })
        .into_owned()
}

const REDACTED_USER_SEGMENT: &str = "<user>";

/// Env home dir (`HOME`/`USERPROFILE`), cached for the export hot path.
static HOME_DIR: LazyLock<Option<String>> = LazyLock::new(|| {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
});

/// Env usernames (`USERNAME`/`USER`), deduped; the 3-char floor avoids folding short generic segments.
static USERNAMES: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut names: Vec<String> = Vec::new();
    for var in ["USERNAME", "USER"] {
        if let Ok(name) = std::env::var(var) {
            let trimmed = name.trim();
            if trimmed.len() >= 3 && !names.iter().any(|u| u.eq_ignore_ascii_case(trimmed)) {
                names.push(trimmed.to_owned());
            }
        }
    }
    names
});

/// True for any char that can't continue a path/username segment: alphanumerics
/// and `_`/`-`/`.` continue one (`/Users/bob` won't fold into `/Users/bobby`),
/// everything else ends it (so `/Users/bob: denied` still collapses).
fn is_segment_boundary(c: char) -> bool {
    !(c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Backstop for headless contexts where `$HOME`/`$USER` are unset.
/// The match is case-sensitive (`/Users`, `/home`, `\Users`) so it won't mangle REST `/users/` paths.
static HOME_ROOT_USER_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"([/\\](?:Users|home)[/\\])([^/\\]+)"));

/// Collapse `$HOME` to `~` and whole path segments equal to the OS username to `<user>`.
pub fn redact_user_paths(input: &str) -> Cow<'_, str> {
    redact_user_paths_with_backstop(input, HOME_DIR.as_deref(), USERNAMES.as_slice())
}

fn redact_user_paths_with_backstop<'a>(
    input: &'a str,
    home: Option<&str>,
    usernames: &[String],
) -> Cow<'a, str> {
    let env_scrubbed = redact_user_paths_env(input, home, usernames);
    // The regex backstop runs ONLY when env is unavailable
    // Otherwise the pass above is authoritative and the regex would over-redact (`/Users/Shared`, REST `/users/<id>`, etc.)
    if home.is_some() || !usernames.is_empty() {
        return env_scrubbed;
    }
    match HOME_ROOT_USER_REGEX.replace_all(env_scrubbed.as_ref(), "${1}<user>") {
        Cow::Owned(o) => Cow::Owned(o),
        Cow::Borrowed(_) => env_scrubbed,
    }
}

fn redact_user_paths_env<'a>(
    input: &'a str,
    home: Option<&str>,
    usernames: &[String],
) -> Cow<'a, str> {
    let stage1 = match home {
        Some(home) if !home.is_empty() && input.contains(home) => {
            Cow::Owned(replace_home_prefix(input, home))
        }
        _ => Cow::Borrowed(input),
    };
    if !usernames.is_empty() {
        let stage2 = redact_username_segments(stage1.as_ref(), usernames);
        if stage2 != stage1.as_ref() {
            return Cow::Owned(stage2);
        }
    }
    match stage1 {
        Cow::Owned(s) if s != input => Cow::Owned(s),
        _ => Cow::Borrowed(input),
    }
}

/// Whole-segment `home` -> `~` so `/Users/bob` doesn't fold over `/Users/bobby/...`.
fn replace_home_prefix(input: &str, home: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find(home) {
        let (before, tail) = rest.split_at(idx);
        let after = &tail[home.len()..];
        let prev_ok = before.chars().last().is_none_or(is_segment_boundary);
        let next_ok = after.chars().next().is_none_or(is_segment_boundary);
        out.push_str(before);
        if prev_ok && next_ok {
            out.push('~');
        } else {
            out.push_str(home);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Replace whole `/`- or `\`-delimited segments equal to a username with `<user>`.
/// Case-insensitive on Windows (NTFS), case-sensitive elsewhere.
fn redact_username_segments(value: &str, usernames: &[String]) -> String {
    let mut out = String::with_capacity(value.len());
    let mut buf = String::new();
    for ch in value.chars() {
        if is_segment_boundary(ch) {
            push_username_segment(&mut out, &buf, usernames);
            buf.clear();
            out.push(ch);
        } else {
            buf.push(ch);
        }
    }
    push_username_segment(&mut out, &buf, usernames);
    out
}

fn push_username_segment(out: &mut String, segment: &str, usernames: &[String]) {
    let matches = if cfg!(windows) {
        usernames.iter().any(|u| u.eq_ignore_ascii_case(segment))
    } else {
        usernames.iter().any(|u| u == segment)
    };
    out.push_str(if matches {
        REDACTED_USER_SEGMENT
    } else {
        segment
    });
}

/// Uses `form_urlencoded::Serializer` so the placeholder isn't percent-encoded.
pub fn redact_url(url: &mut url::Url) {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_fragment(None);

    let Some(query) = url.query().map(str::to_owned) else {
        return;
    };
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| {
            let key = k.into_owned();
            let value = if SENSITIVE_QUERY_PARAMS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&key))
            {
                REDACTED_URL_VALUE.to_owned()
            } else {
                v.into_owned()
            };
            (key, value)
        })
        .collect();
    if pairs.is_empty() {
        url.set_query(None);
        return;
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &pairs {
        serializer.append_pair(k, v);
    }
    url.set_query(Some(&serializer.finish()));
}

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("invalid regex `{pattern}`: {e}"))
}
