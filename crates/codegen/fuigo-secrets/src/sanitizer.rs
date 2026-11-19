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
    LazyLock::new(|| compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-]{16,})\b"));
/// Bare JWT (`eyJ...header.payload.signature`) with no `Bearer`/`sk-` prefix, the shape used by deployment keys and OIDC tokens.
static JWT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"));
/// 8-char value floor to avoid false positives on short values. The keyword may follow an identifier prefix
/// (`GITHUB_TOKEN`, `DB_PASSWORD`) and may be closed by a quote before the separator (`"password": "..."`), audit
/// S11-F2. The keyword must still end the name (`tokens`, `token_count` do not match). The prefix is capped at 64
/// characters and has no `\b` anchor: an unbounded prefix lets the engine's reverse scan from each keyword hit walk
/// back over the whole identifier run, which is quadratic on a long run holding many keywords.
static SECRET_ASSIGNMENT_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r#"(?ix)
        (
            [a-z0-9_]{{0,64}}{CREDENTIAL_NAME}
        )
        (["']?)
        (\s*[:=]\s*)
        (["']?)
        ([^\s"',&]{{8,}})
        "#
    ))
});

/// The credential words a [`SECRET_ASSIGNMENT_REGEX`] name ends in (verbose syntax, case-insensitive there).
const CREDENTIAL_NAME: &str = r"(?:
                api[_-]?key
              | (?:access|refresh|id)[_-]token
              | token
              | secret(?:[_-](?:access[_-])?key)?
              | client[_-]secret
              | password
            )";

/// A percent-decoded URL query or fragment key that the assignment rule reads as a credential name: one that ends in a
/// [`CREDENTIAL_NAME`] word, whatever comes before it (`db_password`, `x.api-key`, `MyToken`). Through 1.0.45 the URL
/// was re-serialised with its keys decoded and the assignment rule then ran over it, so `?db_pass%77ord=...` lost its
/// value (u46 r8 H); an exact list of key names is not enough.
static CREDENTIAL_KEY_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(&format!(r"(?ix) {CREDENTIAL_NAME} \z")));

/// The end of an assignment value that is itself the name of the next assignment, with or without its separator
/// (`abc(secret_key=`, `abc(client-secret:`, `abc("password`), see [`span_pass`].
static TRAILING_CREDENTIAL_NAME_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    compile(&format!(
        r"(?ix) [a-z0-9_]{{0,64}} {CREDENTIAL_NAME} [:=]? \z"
    ))
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
fn assignment_value_is_benign(
    name: &str,
    value: &str,
    quoted: bool,
    url_context: Option<(&str, usize)>,
) -> bool {
    let value = value.trim_end_matches(';');
    let password_name = name.to_ascii_lowercase().ends_with("password");
    if (value.ends_with("...") || value.ends_with('\u{2026}'))
        && !password_name
        && !url_context.is_some_and(|(input, start)| {
            url_rewrite_drops_ellipsis(input, start, start + value.len())
        })
    {
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
    code && (!only_dots_and_colons || names_a_credential(value, password_name))
}

/// Whether the telemetry URL rewrite removes the ellipsis that ends an assignment value (`input[value_start..value_end]`,
/// trailing `;` already left out). Through 1.0.45 the URL pass ran first and the assignment rule saw its output, so
/// the ellipsis counted as a placeholder only if it survived that rewrite (u46 spans4). The span redactor reads the
/// original text and must decide the same way. The ellipsis does not survive when it sits in a fragment (dropped
/// whole), is `\u{2026}` anywhere in a URL (the parser percent-encodes it), ends the value of a query pair under a
/// [`SENSITIVE_QUERY_PARAMS`] key (replaced whole), or ends a query pair with no `=` (re-serialised as `key=`). The
/// URL is the one `https?://[^\s"'<>(){}\[\],;`]+` that covers the value's end, which can run on past the value
/// (the value stops at `&`, the URL does not); it must also parse.
fn url_rewrite_drops_ellipsis(input: &str, value_start: usize, value_end: usize) -> bool {
    let ends_url = |c: char| c.is_whitespace() || "\"'<>(){}[],;`".contains(c);
    let run_start = input[..value_end].rfind(ends_url).map_or(0, |at| {
        at + input[at..].chars().next().map_or(1, char::len_utf8)
    });
    let run_end = input[value_end..]
        .find(ends_url)
        .map_or(input.len(), |at| value_end + at);
    let run = &input[run_start..run_end];
    let mut from = 0;
    let url_at = loop {
        let Some(at) = run[from..].find("http") else {
            return false;
        };
        let at = from + at;
        let scheme = if run[at..].starts_with("https://") {
            8
        } else if run[at..].starts_with("http://") {
            7
        } else {
            from = at + 4;
            continue;
        };
        if run.len() > at + scheme {
            break at;
        }
        from = at + scheme;
    };
    if run_start + url_at >= value_end || value_start > value_end {
        return false;
    }
    let url = &run[url_at..];
    if url::Url::parse(url).is_err() {
        return false;
    }
    let end = value_end - (run_start + url_at);
    if input[..value_end].ends_with('\u{2026}') {
        return true;
    }
    let hash = url.find('#');
    if hash.is_some_and(|h| h < end) {
        return true;
    }
    let Some(query) = url.find('?').filter(|&q| q < end) else {
        return false;
    };
    let pair_start = url[..end]
        .rfind('&')
        .map_or(query + 1, |at| (at + 1).max(query + 1));
    let pair_end = url[end..].find(['&', '#']).map_or(url.len(), |at| end + at);
    let pair = &url[pair_start..pair_end];
    !pair.contains('=')
        || url::form_urlencoded::parse(pair.as_bytes())
            .next()
            .is_some_and(|(key, _)| {
                SENSITIVE_QUERY_PARAMS
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&key))
            })
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
///
/// Delta review D3-06: after a password name a literal can itself contain a credential word
/// (`correct.horse.secret`), so there the credential word must end the value and the value must read as a field
/// access: two parts (`user.password`) or a path that starts at a familiar object (`request.body.password`).
fn names_a_credential(value: &str, after_password_name: bool) -> bool {
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
    const OBJECTS: [&str; 17] = [
        "self", "this", "args", "opts", "options", "config", "cfg", "conf", "env", "params",
        "request", "req", "body", "data", "user", "settings", "ctx",
    ];
    let value = value.to_ascii_lowercase();
    let parts: Vec<&str> = value.split(['.', ':', '_']).collect();
    if after_password_name {
        return parts.last().is_some_and(|last| WORDS.contains(last))
            && (parts.len() == 2 || parts.first().is_some_and(|first| OBJECTS.contains(first)));
    }
    parts.iter().any(|part| WORDS.contains(part))
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

/// Whether the value under each [`SENSITIVE_QUERY_PARAMS`] key is written as [`REDACTED`] rather than
/// [`REDACTED_URL_VALUE`]: the keys that are themselves credential names to the assignment rule (`token`, `api_key`,
/// `password`, ...). This is the format the scrub has always produced (the URL pass wrote `key=redacted`, then the
/// assignment pass turned `token=redacted` into the marker), now chosen up front.
static QUERY_KEY_USES_MARKER: LazyLock<Vec<bool>> = LazyLock::new(|| {
    SENSITIVE_QUERY_PARAMS
        .iter()
        .map(|key| SECRET_ASSIGNMENT_REGEX.is_match(&format!("{key}={REDACTED_URL_VALUE}")))
        .collect()
});

/// Gate for [`query_value_spans`] in `MATCH_ANY`: a scheme-shaped token ending in `:`, then a `?` or `#` in the same
/// run of non-blank, unquoted text (TAB/LF/CR do not end the run: the parser drops them). Over-approximates the scan,
/// which decides precisely; linear.
static QUERY_GATE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"[A-Za-z][A-Za-z0-9+.\t\n\r-]*:[\t\n\r[^\s"'<>`]]*[?#]"#));

/// Gate for [`userinfo_removals`] in `MATCH_ANY`: a scheme-shaped token ending in `:` (TAB/LF/CR may sit anywhere,
/// the parser drops them) with an `@` somewhere after it. Over-approximates the scan, which decides precisely; linear.
static USERINFO_GATE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?s)[A-Za-z][A-Za-z0-9+.\t\n\r-]*:.*@"));

/// Index of each detector's pattern in [`MATCH_ANY`]; a detector runs only when its pattern matched.
mod gate {
    pub const API_KEY: usize = 0;
    pub const AWS: usize = 1;
    pub const GITHUB: usize = 2;
    pub const VENDOR: usize = 3;
    pub const OTHER_VENDOR: usize = 4;
    pub const BASIC: usize = 5;
    pub const GOOGLE: usize = 6;
    pub const PEM: usize = 7;
    pub const PEM_TORN: usize = 8;
    pub const BEARER: usize = 9;
    pub const JWT: usize = 10;
    pub const QUERY: usize = 11;
    pub const USERINFO: usize = 12;
    pub const ASSIGNMENT: usize = 13;
    pub const PERCENT: usize = 14;
}

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
        QUERY_GATE_REGEX.as_str(),
        USERINFO_GATE_REGEX.as_str(),
        SECRET_ASSIGNMENT_REGEX.as_str(),
        // An escape of an ASCII byte, for [`percent_decoded_assignment_spans`].
        "%[0-7][0-9A-Fa-f]",
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

/// What a detector asks for a byte range of the ORIGINAL input (u46 spans, the stop-rule root fix: detectors used to
/// run as sequential rewrites, each reading the previous one's output, so every reorder leaked a new case).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpanKind {
    /// Replace with [`REDACTED`].
    Secret,
    /// A URL query or fragment value under a [`SENSITIVE_QUERY_PARAMS`] key: replace with this placeholder
    /// ([`REDACTED`] or [`REDACTED_URL_VALUE`], see [`QUERY_KEY_USES_MARKER`]).
    QueryValue(&'static str),
    /// Remove (URL userinfo, `https://user:pw@h` -> `https://h`).
    Remove,
}

#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    end: usize,
    kind: SpanKind,
    /// [`SpanKind::Remove`]: where the scheme's `:` is. An assignment value: where its name starts. See
    /// [`settle_userinfo_overlaps`].
    anchor: Option<usize>,
}

impl Span {
    /// A query value or fragment, from [`query_value_spans`].
    fn is_url_part(&self) -> bool {
        matches!(self.kind, SpanKind::QueryValue(_))
    }

    fn secret(start: usize, end: usize) -> Self {
        Span {
            start,
            end,
            kind: SpanKind::Secret,
            anchor: None,
        }
    }
}

/// `telemetry`: the [`redact_secrets`] flavour (URL userinfo removed and sensitive query/fragment values redacted;
/// only complete PEM blocks). Otherwise the [`redact_credential_shapes`] flavour (URLs untouched; torn PEM blocks too).
///
/// The redaction is [`span_pass`]: every detector reads the original input. Removing a userinfo or writing a marker
/// can join text into something a second reading sees differently (`token://  x TOKEN=:h@p` loses its blanks and
/// becomes `token://[REDACTED_SECRET]`), so the result is read again, with the same full span pass, until nothing
/// changes: a later pass only ever redacts more, never un-redacts, and a scrubbed text is a fixed point. Two passes
/// for almost any text; capped at [`MAX_SPAN_PASSES`], so linear.
fn redact_shapes(input: &str, telemetry: bool) -> Cow<'_, str> {
    let mut out = match span_pass(input, telemetry) {
        Cow::Borrowed(_) => return Cow::Borrowed(input),
        Cow::Owned(out) => out,
    };
    for _ in 1..MAX_SPAN_PASSES {
        match span_pass(&out, telemetry) {
            Cow::Borrowed(_) => break,
            Cow::Owned(next) => out = next,
        }
    }
    Cow::Owned(out)
}

/// Passes of [`redact_shapes`] at most (the second finds nothing for almost every text).
const MAX_SPAN_PASSES: usize = 4;

/// One redaction of `input`: every detector runs on it and returns byte ranges; no detector sees another's output.
/// The ranges are merged ([`apply_spans`]) and written in one pass over `input`, every other byte kept as it was.
/// Linear in the input.
fn span_pass(input: &str, telemetry: bool) -> Cow<'_, str> {
    let hits = MATCH_ANY.matches(input);
    if !hits.matched_any() {
        return Cow::Borrowed(input);
    }
    let mut spans: Vec<Span> = Vec::new();
    if hits.matched(gate::PEM) {
        spans.extend(
            PEM_PRIVATE_KEY_REGEX
                .find_iter(input)
                .map(|m| Span::secret(m.start(), m.end())),
        );
    }
    if !telemetry && hits.matched(gate::PEM_TORN) {
        torn_pem_spans(input, &mut spans);
    }
    for (index, regex) in [
        (gate::API_KEY, &*API_KEY_PREFIX_REGEX),
        (gate::AWS, &*AWS_ACCESS_KEY_REGEX),
        (gate::GITHUB, &*GITHUB_TOKEN_REGEX),
        (gate::VENDOR, &*VENDOR_TOKEN_REGEX),
        (gate::OTHER_VENDOR, &*OTHER_VENDOR_TOKEN_REGEX),
        (gate::GOOGLE, &*GOOGLE_API_KEY_REGEX),
        (gate::JWT, &*JWT_REGEX),
    ] {
        if hits.matched(index) {
            spans.extend(
                regex
                    .find_iter(input)
                    .map(|m| Span::secret(m.start(), m.end())),
            );
        }
    }
    // A plain lower-case word after `Authorization: Basic` is prose (review S11-F2-R1); anything else (a digit, an
    // upper-case letter, one of `+ / =`) is taken for base64 of `user:password`, letters-only credentials included.
    // The header name and scheme are kept.
    if hits.matched(gate::BASIC) {
        for c in BASIC_AUTH_REGEX.captures_iter(input) {
            // The groups always take part; should one not, the whole match is redacted (fail closed, no panic).
            let Some(value) = c.get(2).or_else(|| c.get(0)) else {
                continue;
            };
            if !value.as_str().chars().all(|ch| ch.is_ascii_lowercase()) {
                spans.push(Span::secret(value.start(), value.end()));
            }
        }
    }
    if hits.matched(gate::BEARER) {
        for c in BEARER_TOKEN_REGEX.captures_iter(input) {
            let Some(value) = c.get(1).or_else(|| c.get(0)) else {
                continue;
            };
            spans.push(Span::secret(value.start(), value.end()));
        }
    }
    if hits.matched(gate::ASSIGNMENT) {
        assignment_spans(input, telemetry.then_some(input), None, |at| at, &mut spans);
    }
    if telemetry && hits.matched(gate::PERCENT) {
        percent_decoded_assignment_spans(input, &mut spans);
    }
    if telemetry {
        if hits.matched(gate::USERINFO) {
            match userinfo_removals(input) {
                Some(removals) => spans.extend(removals),
                // Unreachable for any real log record (4 GiB); fail closed.
                None => return Cow::Owned(REDACTED.to_owned()),
            }
        }
        if hits.matched(gate::QUERY) {
            query_value_spans(input, &mut spans);
            empty_credential_key_spans(input, &mut spans);
        }
    }
    settle_userinfo_overlaps(input.as_bytes(), &mut spans);
    if telemetry {
        keep_authority_ends(input.as_bytes(), &mut spans);
    }
    apply_spans(input, spans)
}

/// The [`SECRET_ASSIGNMENT_REGEX`] values in `text` that are not plainly benign, as [`Span::secret`]s of the input:
/// `at` maps a byte offset of `text` to the input (identity when `text` is the input). `url_context`: the input, for
/// the telemetry ellipsis rule ([`url_rewrite_drops_ellipsis`]); only when `text` is the input. `escaped`: the input,
/// when `text` is its percent-decoded view; a value is then benign only if its spelling in the input is benign too
/// (`$T%4F%4BEN%2e%2e` is no `$TOKEN...` placeholder: 1.0.45 never decoded it outside a URL host or query key).
fn assignment_spans(
    text: &str,
    url_context: Option<&str>,
    escaped: Option<&str>,
    at: impl Fn(usize) -> usize,
    spans: &mut Vec<Span>,
) {
    for first in SECRET_ASSIGNMENT_REGEX.captures_iter(text) {
        let mut c = first;
        loop {
            let Some(whole) = c.get(0) else {
                break;
            };
            let (name, value) = (c.get(1).unwrap_or(whole), c.get(5).unwrap_or(whole));
            let quoted = c.get(4).is_some_and(|q| !q.as_str().is_empty());
            let url_context = url_context.map(|input| (input, value.start()));
            let benign =
                assignment_value_is_benign(name.as_str(), value.as_str(), quoted, url_context)
                    && escaped.is_none_or(|input| {
                        let spelled = &input[at(value.start())..at(value.end())];
                        assignment_value_is_benign(name.as_str(), spelled, quoted, None)
                    });
            if !benign {
                spans.push(Span {
                    anchor: Some(at(name.start())),
                    ..Span::secret(at(value.start()), at(value.end()))
                });
            }
            // A value that ends in the next assignment's name (`token=abc(secret_key='s3cret'`: the value class
            // stops only at a blank, a quote, `,` or `&`) would hide that assignment from the scan, which resumes
            // after the match. Through 1.0.45 the URL pass usually cut such a run first (u46 spans3, found by the
            // differential test). Read the next assignment from that name; each one starts past the last, so the
            // chain stays linear.
            let Some(tail) = TRAILING_CREDENTIAL_NAME_REGEX.find(value.as_str()) else {
                break;
            };
            let from = value.start() + tail.start();
            match SECRET_ASSIGNMENT_REGEX.captures_at(text, from) {
                Some(next)
                    if next.get(0).is_some_and(|m| m.start() == from)
                        && next.get(5).is_some_and(|v| v.end() > value.end()) =>
                {
                    c = next;
                }
                _ => break,
            }
        }
    }
}

/// u46 spans5: through 1.0.45 the telemetry scrub re-serialised every `http(s)` URL before the assignment rule ran,
/// and the parser percent-decodes hosts (`https://%70assword=swordfish987/` became `https://password=...`) and query
/// keys, so a credential assignment spelled with escapes lost its value. Rather than follow the parser component by
/// component, the assignment rule also reads a percent-decoded view of the whole input (hosts, paths, userinfo,
/// queries, fragments, and text outside URLs alike), and a value found there is redacted at its original bytes (the
/// escapes of its first and last character included). Only escapes of ASCII bytes are decoded, so the view stays
/// UTF-8 and a decoded byte maps to exactly one escape; `%25` decodes once. Escapes of the characters that end an
/// assignment value (blanks, quotes, `,` `&`) stay escaped: 1.0.45 re-encoded them, so `%26code=` did not cut the
/// value short there and the text after it went with the value (found by the 100k differential run). It only adds spans: over-redaction of an
/// escaped assignment outside a URL is accepted. Linear: one decode, one assignment scan.
fn percent_decoded_assignment_spans(input: &str, spans: &mut Vec<Span>) {
    let bytes = input.as_bytes();
    let hex = |at: usize| bytes.get(at).and_then(|&b| (b as char).to_digit(16));
    let mut decoded = Vec::with_capacity(bytes.len());
    // at[i]: where decoded byte i starts in the input; at[decoded.len()] = input.len().
    let mut at = Vec::with_capacity(bytes.len() + 1);
    let mut i = 0;
    while i < bytes.len() {
        at.push(i);
        if bytes[i] == b'%'
            && let (Some(high), Some(low)) = (hex(i + 1), hex(i + 2))
            && high < 8
            && !b" \t\n\r\x0b\x0c\"',&".contains(&((high * 16 + low) as u8))
        {
            decoded.push((high * 16 + low) as u8);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    at.push(bytes.len());
    // Only ASCII escapes were decoded and every other byte copied, so this is UTF-8; should it not be, add nothing
    // (the plain scan already ran over the input).
    let Ok(decoded) = String::from_utf8(decoded) else {
        return;
    };
    if decoded.len() == input.len() {
        return;
    }
    assignment_spans(&decoded, None, Some(input), |d| at[d], spans);
}

/// PEM blocks with no END line ([`PEM_UNTERMINATED_PRIVATE_KEY_REGEX`]), looked for only between the complete blocks
/// already in `spans`, so a complete block is never read as a torn one. `find_at` keeps the line anchors reading the
/// whole input. Each gap's search stops at the next complete block's BEGIN marker, which the pattern also matches,
/// so the input is scanned once.
fn torn_pem_spans(input: &str, spans: &mut Vec<Span>) {
    let blocks: Vec<(usize, usize)> = spans.iter().map(|s| (s.start, s.end)).collect();
    let mut from = 0;
    for (block_start, block_end) in blocks
        .into_iter()
        .chain(std::iter::once((input.len(), input.len())))
    {
        let mut at = from;
        while at < block_start {
            let Some(m) = PEM_UNTERMINATED_PRIVATE_KEY_REGEX.find_at(input, at) else {
                break;
            };
            if m.start() >= block_start {
                break;
            }
            spans.push(Span::secret(m.start(), m.end()));
            at = m.end();
        }
        from = block_end;
    }
}

/// A removal that a secret value starts inside of and runs past (the removal's last `@` is part of the value) is
/// cut back so the two no longer overlap; the value is still redacted whole, and with it the `@` that made the text
/// before it a userinfo. Where the value is an assignment whose name begins on a later line than the URL's scheme
/// (`API=https://api.example.com\nDB_PASSWORD=p@ssw0rd`, u46 r4 H1), the removal stops at that line break so the
/// name is kept, when nothing between the line start and the name holds a `:` or `@` (a username or password the
/// parser would read): `API=https://\nDB_PASSWORD=[REDACTED_SECRET]`. Otherwise the removal stops at the value.
fn settle_userinfo_overlaps(raw: &[u8], spans: &mut Vec<Span>) {
    if !spans.iter().any(|s| s.kind == SpanKind::Remove) {
        return;
    }
    let mut values: Vec<Span> = spans
        .iter()
        .filter(|s| s.kind != SpanKind::Remove)
        .copied()
        .collect();
    if values.is_empty() {
        return;
    }
    values.sort_unstable_by_key(|s| s.start);
    // last_break[i]: one past the last LF/CR before i, or 0. Built on first use.
    let mut last_break: Vec<u32> = Vec::new();
    for removal in spans.iter_mut().filter(|s| s.kind == SpanKind::Remove) {
        let colon = removal.anchor.unwrap_or(removal.start);
        let first = values.partition_point(|v| v.start <= removal.start);
        let Some(value) = values[first..]
            .iter()
            .take_while(|v| v.start < removal.end)
            .find(|v| v.end > removal.end)
        else {
            continue;
        };
        if last_break.is_empty() {
            last_break = vec![0; raw.len() + 1];
            for (i, &b) in raw.iter().enumerate() {
                last_break[i + 1] = if matches!(b, b'\n' | b'\r') {
                    i as u32 + 1
                } else {
                    last_break[i]
                };
            }
        }
        // Nothing between `from` and the assignment's name may be read as part of a credential.
        let name_is_clean = |from: usize| {
            value.anchor.is_some_and(|name| {
                name <= from || !raw[from..name].iter().any(|b| matches!(b, b':' | b'@'))
            })
        };
        let line_break = last_break[value.start] as usize;
        removal.end = if line_break > colon + 1 {
            let lb = line_break - 1;
            if lb >= removal.start {
                if name_is_clean(lb + 1) {
                    // Keep a CRLF whole.
                    if lb > removal.start && raw[lb] == b'\n' && raw[lb - 1] == b'\r' {
                        lb - 1
                    } else {
                        lb
                    }
                } else {
                    value.start
                }
            } else if name_is_clean(removal.start) {
                // The value's line starts the authority (`ftp:\\\nDB_PASSWORD=p@ss`): nothing to remove.
                removal.start
            } else {
                value.start
            }
        } else {
            value.start
        };
    }
    spans.retain(|s| s.start < s.end);
}

/// u46 spans6 (found by the fuzz target): no redaction takes the byte that ends a URL authority opened before it.
/// In `s:?t://token=?'@token=?'@token=v` the query value `?` under the key `t://token` ended the authority of
/// `t://`; written as the marker, the next pass read `token=[REDACTED_SECRET]'@` as a userinfo and removed it, which
/// exposed the next hop the same way: two passes per hop, so a long chain was cut off half-done at
/// [`MAX_SPAN_PASSES`]. Every non-removal span that starts inside an authority (as [`userinfo_removals`] reads it)
/// and runs over that authority's terminator (`/ ? #`, and `\` after a special scheme) is split there: the
/// terminator is kept, the text on each side is still redacted. The URL keeps its shape, so the authority and any
/// userinfo removal are the same on every pass. Linear: authorities open at a position share one terminator per kind.
fn keep_authority_ends(raw: &[u8], spans: &mut Vec<Span>) {
    if !raw.contains(&b':')
        || u32::try_from(raw.len()).is_err()
        || spans.iter().all(|s| s.kind == SpanKind::Remove)
    {
        return;
    }
    let scan = authority_scan(raw);
    if scan.starts.is_empty() {
        return;
    }
    let c: &[u8] = &scan.c;
    let n = c.len();
    // (start, terminator, special) in original bytes, for each authority that has a terminator, by start.
    let mut authorities: Vec<(usize, usize, bool)> = Vec::with_capacity(scan.starts.len());
    for special in [true, false] {
        if !scan.starts.iter().any(|&(_, s, _)| s == special) {
            continue;
        }
        let next = next_terminators(c, special);
        for &(s, kind, _) in &scan.starts {
            let end = next[s] as usize;
            if kind == special && end < n {
                let start = if s < n { scan.at(s) } else { raw.len() };
                authorities.push((start, scan.at(end), special));
            }
        }
    }
    if authorities.is_empty() {
        return;
    }
    authorities.sort_unstable_by_key(|a| a.0);
    let mut order: Vec<usize> = (0..spans.len())
        .filter(|&i| spans[i].kind != SpanKind::Remove)
        .collect();
    order.sort_unstable_by_key(|&i| spans[i].start);
    // The furthest terminator of the authorities started so far, per kind: an authority still open at a position
    // ends at the first terminator of its kind after it, so all open ones of a kind share it, and it is this one.
    let (mut special_end, mut other_end) = (None::<usize>, None::<usize>);
    let mut next_authority = 0;
    let mut pieces: Vec<Span> = Vec::new();
    for i in order {
        let span = spans[i];
        while let Some(&(start, end, special)) = authorities.get(next_authority) {
            if start > span.start {
                break;
            }
            let slot = if special {
                &mut special_end
            } else {
                &mut other_end
            };
            *slot = Some(slot.map_or(end, |e: usize| e.max(end)));
            next_authority += 1;
        }
        let mut cuts: Vec<usize> = [special_end, other_end]
            .into_iter()
            .flatten()
            .filter(|&e| e >= span.start && e < span.end)
            .collect();
        if cuts.is_empty() {
            continue;
        }
        cuts.sort_unstable();
        cuts.dedup();
        let mut from = span.start;
        for cut in cuts {
            if cut > from {
                pieces.push(Span {
                    start: from,
                    end: cut,
                    ..span
                });
            }
            from = cut + 1;
        }
        if span.end > from {
            pieces.push(Span {
                start: from,
                ..span
            });
        }
        spans[i].end = spans[i].start;
    }
    spans.retain(|s| s.start < s.end);
    spans.extend(pieces);
}

/// Merges the ranges and writes the result in one pass over `input`. Overlapping ranges, and value ranges that touch,
/// become one; a merged range is removed when one userinfo removal covers it whole, is written `key=redacted` when it
/// is only [`REDACTED_URL_VALUE`] query values, and is [`REDACTED`] otherwise (when kinds overlap the value placeholder
/// wins). A range that holds a URL query value or fragment (the only ranges, besides PEM blocks and removals, that
/// reach across TAB/LF/CR, as the parser does) gets one marker per stretch between those characters, which are kept:
/// the assignment rule ends a value at them, so a single marker there would be read on the next pass as `name=` + marker
/// + whatever follows (u46 r7, found by the generated-URL oracle's fixed-point check). Unchanged text is returned borrowed.
fn apply_spans(input: &str, mut spans: Vec<Span>) -> Cow<'_, str> {
    if spans.is_empty() {
        return Cow::Borrowed(input);
    }
    // At one start the longest first, and for the same range a value before a removal.
    spans.sort_unstable_by_key(|s| {
        (
            s.start,
            std::cmp::Reverse(s.end),
            s.kind == SpanKind::Remove,
        )
    });
    let mut out = String::with_capacity(input.len());
    let mut copied = 0;
    let mut i = 0;
    while i < spans.len() {
        let first = spans[i];
        let start = first.start;
        let mut end = first.end;
        let mut removed = first.kind == SpanKind::Remove;
        let mut url_value_only = first.kind == SpanKind::QueryValue(REDACTED_URL_VALUE);
        let mut url_part = first.is_url_part();
        i += 1;
        while let Some(next) = spans.get(i) {
            let touches_value = next.start == end && !removed && next.kind != SpanKind::Remove;
            if next.start >= end && !touches_value {
                break;
            }
            if next.end > end {
                end = next.end;
                removed = false;
            }
            url_value_only &= next.kind == SpanKind::QueryValue(REDACTED_URL_VALUE);
            url_part |= next.is_url_part();
            i += 1;
        }
        out.push_str(&input[copied..start]);
        if !removed {
            if url_value_only {
                out.push_str(REDACTED_URL_VALUE);
            } else if url_part {
                push_markers_keeping_controls(&mut out, &input[start..end]);
            } else {
                out.push_str(REDACTED);
            }
        }
        copied = end;
    }
    out.push_str(&input[copied..]);
    if out == input {
        Cow::Borrowed(input)
    } else {
        Cow::Owned(out)
    }
}

/// [`REDACTED`] for each stretch of `range` between TAB/LF/CR, which are kept.
fn push_markers_keeping_controls(out: &mut String, range: &str) {
    let mut pending = false;
    for ch in range.chars() {
        if matches!(ch, '\t' | '\n' | '\r') {
            if pending {
                out.push_str(REDACTED);
                pending = false;
            }
            out.push(ch);
        } else {
            pending = true;
        }
    }
    if pending {
        out.push_str(REDACTED);
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

/// Sensitive query and fragment values in every URL-shaped run of the text, as the `url` crate would read them, on
/// the original bytes (u46 r5/r6: an earlier rewrite can no longer hide the rest of a query).
///
/// The parser removes every TAB, LF and CR before it reads anything, so this scan reads the text with them left out
/// (they are skipped, which is the userinfo scanner's normalised view; every range is still in original bytes, u46 r7:
/// `https://h/?x=1<TAB>&code=...` hid the value). A run is text without other whitespace (Unicode, as
/// `char::is_whitespace`; a normal space still ends a URL), quotes, `<`, `>` or backticks. Within a run, once a scheme
/// token (`[A-Za-z][A-Za-z0-9+.-]*:`, any scheme, any case, IPv6 `[::1]` hosts included) has been seen, every `?` or
/// `#` starts a `key=value` pair and so does every `&` after one; a key (TAB/LF/CR dropped, then percent- and
/// `+`-decoded, any case) from [`SENSITIVE_QUERY_PARAMS`] has its non-empty value redacted up to the next `&`, `#` or
/// end of run. A `?` inside a value also starts a pair, so a URL nested in a value (`?next=http://x/?token=...`) is
/// read too. Trailing `. , ; ) ] }` (and TAB/LF/CR) are left to the surrounding prose (`(see https://h/?code=abc).`;
/// only `,` under a key written with the marker, whose value the assignment rule reads up to a `,`); a value that is
/// the marker itself is left alone.
///
/// The fragment of a hierarchical URL (a special scheme, or a scheme followed by `/`: what the parser does not read as
/// cannot-be-a-base) is redacted whole, up to the end of the run less the trailing punctuation above, as the URL pass
/// did through 1.0.45 (u46 r7: an opaque `https://h/#OAuthSecret987` survived the per-key reading). It is written
/// `#redacted` (`#[REDACTED_SECRET]` when it holds a marker key) rather than deleted as 1.0.45 did: a deletion joins the text around it, and the fuzz target
/// found a chain where each deleted fragment exposed a new userinfo and each removed userinfo a new fragment, one more
/// pass every time. A value still open at that `#` runs on through the fragment to the end of the run instead.
/// Over-approximates the parser (any scheme, a `?` inside a userinfo), never under; one pass, each value closed once,
/// each closing position's trailing punctuation measured once (u46 r7: n open values over n trailing dots was
/// quadratic).
fn query_value_spans(text: &str, spans: &mut Vec<Span>) {
    let mut run_has_letter = false;
    let mut seen_scheme = false;
    // A scheme of this run makes the URL hierarchical; `after_colon`: the last kept character was a scheme's `:`.
    let mut hierarchical = false;
    let mut after_colon = false;
    // The last five scheme bytes of the current token run, each with whether a token may start there (the run's first
    // letter, or the first letter after a TAB/LF/CR, which also starts a word), to tell a special scheme.
    let mut tail = [(0u8, false); 5];
    let mut tail_len = 0usize;
    let mut want_start = true;
    let mut in_query = false;
    let mut key_start: Option<usize> = None;
    // The `#` of this run's hierarchical fragment, and whether open values took it in (then they cover it and no
    // removal is pushed: a value closed at the `#` would leave `key=[REDACTED_SECRET]` against the prose after the
    // fragment, which the next pass reads as part of the value).
    let mut fragment: Option<(usize, bool)> = None;
    // The fragment holds a pair under a key written with the marker (`#access_token=...`): it is written with the
    // marker too, which `fuigo-memory` counts; any other fragment is written `redacted`, which it does not, so a docs
    // link such as `https://example.com/guide#overview` is still admitted.
    let mut fragment_marker = false;
    let mut open: Vec<(usize, &'static str)> = Vec::new();
    // Whether `open` holds a value under a key not written with the marker (kept so a `<` costs O(1)).
    let mut open_plain = false;
    let close = |open: &mut Vec<(usize, &'static str)>, end: usize, spans: &mut Vec<Span>| {
        // Values are opened left to right, so the first is the lowest; every value closing here shares one end.
        let Some(&(lowest, _)) = open.first() else {
            return;
        };
        let lowest = lowest.min(end);
        let window = &text[lowest..end];
        let prose_stop = past_marker_end(
            text,
            lowest,
            lowest + window.trim_end_matches(PROSE_TRAILING).len(),
        );
        let marker_stop = lowest + window.trim_end_matches(MARKER_TRAILING).len();
        // Under a marker key the assignment rule reads a value up to a `,` but only to the first TAB/LF/CR: after the
        // last of those inside the value, the prose's trailing punctuation is left as under any other key.
        // A last stretch that starts with the marker keeps it whole (its `]` is not prose).
        let after_control = text[lowest..marker_stop]
            .rfind(['\t', '\n', '\r'])
            .map(|at| {
                let piece = lowest + at + 1;
                let floor = if text[piece..end].starts_with(REDACTED) {
                    piece + REDACTED.len()
                } else {
                    piece
                };
                (lowest + at, prose_stop.max(floor))
            });
        for (start, placeholder) in open.drain(..) {
            let boundary = match after_control {
                _ if placeholder != REDACTED => prose_stop,
                Some((at, stop)) if at >= start => stop,
                _ => marker_stop,
            };
            push_query_value(text, start, end, boundary, placeholder, spans);
        }
    };
    for (i, ch) in text.char_indices() {
        if matches!(ch, '\t' | '\n' | '\r') {
            want_start = true;
            continue;
        }
        // `<`, `>` and a backtick end a URL but not the value of an assignment, which is how 1.0.45 read a query
        // value under a key written with the marker (u46 spans4: `?db_pass%77ord=abc<x>#def` lost `def` to the
        // assignment rule). u46 spans7 (found by the fuzz target): a value cut at a backtick was written
        // `token=[REDACTED_SECRET]` + backtick, the next pass read marker and backtick as one assignment value and
        // took the backtick, joining the run to the text after it, one more hop every two passes.
        let in_marker_value = !open.is_empty() && !open_plain;
        let blank = ch.is_whitespace()
            || matches!(ch, '"' | '\'')
            || (matches!(ch, '<' | '>' | '`') && !in_marker_value);
        let starts_fragment = ch == '#' && seen_scheme && hierarchical && fragment.is_none();
        if starts_fragment {
            fragment = Some((i, !open.is_empty()));
        } else if blank || (fragment.is_none() && (ch == '&' || ch == '#')) {
            close(&mut open, i, spans);
        }
        if blank {
            if let Some((hash, false)) = fragment.take() {
                push_fragment(text, hash, i, fragment_marker, spans);
            }
            fragment_marker = false;
            run_has_letter = false;
            seen_scheme = false;
            hierarchical = false;
            after_colon = false;
            tail_len = 0;
            want_start = true;
            in_query = false;
            key_start = None;
            continue;
        }
        if after_colon {
            hierarchical |= ch == '/';
            after_colon = false;
        }
        if let Some(start) = key_start {
            if ch == '=' {
                // Inside a fragment that is redacted whole there is no value to pick out.
                match (sensitive_query_key(&text[start..i]), fragment) {
                    (Some(placeholder), None) => {
                        if open.is_empty() {
                            open_plain = false;
                        }
                        open_plain |= placeholder != REDACTED;
                        open.push((i + 1, placeholder));
                    }
                    (Some(REDACTED), Some(_)) => fragment_marker = true,
                    _ => {}
                }
                key_start = None;
            } else if matches!(ch, '&' | '#' | '?') {
                key_start = None;
            }
        }
        if ch.is_ascii() && is_scheme_byte(ch as u8) {
            let b = ch as u8;
            run_has_letter |= b.is_ascii_alphabetic();
            let starts = want_start && b.is_ascii_alphabetic();
            want_start &= !starts;
            tail.rotate_left(1);
            tail[4] = (b, starts);
            tail_len += 1;
        } else {
            if ch == ':' && run_has_letter {
                seen_scheme = true;
                if tail_is_special_scheme(&tail, tail_len) {
                    hierarchical = true;
                } else {
                    after_colon = true;
                }
            }
            run_has_letter = false;
            tail_len = 0;
            want_start = true;
        }
        if seen_scheme && matches!(ch, '?' | '#') {
            in_query = true;
            key_start = Some(i + 1);
        } else if in_query && ch == '&' {
            key_start = Some(i + 1);
        }
    }
    close(&mut open, text.len(), spans);
    if let Some((hash, false)) = fragment {
        push_fragment(text, hash, text.len(), fragment_marker, spans);
    }
}

/// Trailing characters a value or fragment leaves to the prose after it; under a marker key only `,` (see
/// [`query_value_spans`]). TAB/LF/CR are never part of what the parser reads.
const PROSE_TRAILING: &[char] = &['.', ',', ';', ')', ']', '}', '\t', '\n', '\r'];
const MARKER_TRAILING: &[char] = &[',', '\t', '\n', '\r'];

/// `stop` moved past a `]` that closes a marker (u46 spans6): the trailing-punctuation rule takes `]` for prose, so
/// `?[REDACTED_SECRET]` at a value's end lost its `]` to it and was written `[REDACTED_SECRET]]`, one more `]` on
/// every pass. Only a marker wholly inside the value (from `from`) counts.
fn past_marker_end(text: &str, from: usize, stop: usize) -> usize {
    let open = &REDACTED[..REDACTED.len() - 1];
    if text[from..stop].ends_with(open) && text.as_bytes().get(stop) == Some(&b']') {
        stop + 1
    } else {
        stop
    }
}

/// Whether the token ending the scheme bytes in `tail` (the last `len` of them, at most five kept) is a special
/// scheme starting where a token may start.
fn tail_is_special_scheme(tail: &[(u8, bool); 5], len: usize) -> bool {
    ["http", "https", "ws", "wss", "ftp", "file"]
        .iter()
        .any(|s| {
            let n = s.len();
            let token = &tail[5 - n..];
            len >= n
                && token[0].1
                && token
                    .iter()
                    .zip(s.bytes())
                    .all(|(&(b, _), c)| b.eq_ignore_ascii_case(&c))
        })
}

/// Redacts a fragment (`hash` is its `#`, which is kept) up to `end` less trailing punctuation: with the marker, per
/// stretch between TAB/LF/CR like a marker-key value, when `marker` (a marker key inside) or when it already starts
/// with the marker; otherwise `redacted`, as under any other key; a last stretch that starts with the marker keeps it whole,
/// so a scrubbed fragment is read the same again. A fragment of nothing but trailing punctuation, or an empty one,
/// holds nothing and stays.
fn push_fragment(text: &str, hash: usize, end: usize, marker: bool, spans: &mut Vec<Span>) {
    let start = hash + 1;
    let body = &text[start..end];
    let last_piece = start
        + body
            .trim_end_matches(MARKER_TRAILING)
            .rfind(['\t', '\n', '\r'])
            .map_or(0, |at| at + 1);
    let floor = if text[last_piece..end].starts_with(REDACTED) {
        last_piece + REDACTED.len()
    } else {
        // Trailing punctuation is taken only from the last stretch, never across a TAB/LF/CR into a marker.
        last_piece
    };
    let stop = past_marker_end(
        text,
        start,
        start + body.trim_end_matches(PROSE_TRAILING).len(),
    )
    .max(floor);
    if stop > start {
        spans.push(Span {
            start,
            end: stop,
            kind: SpanKind::QueryValue(if marker || body.starts_with(REDACTED) {
                REDACTED
            } else {
                REDACTED_URL_VALUE
            }),
            anchor: None,
        });
    }
}

/// `boundary`: where the value's text ends once trailing punctuation is left out, measured over the whole closing
/// window (so at or before `start` when the value is nothing but such punctuation).
fn push_query_value(
    text: &str,
    start: usize,
    end: usize,
    boundary: usize,
    placeholder: &'static str,
    spans: &mut Vec<Span>,
) {
    if end <= start {
        return;
    }
    let mut stop = boundary.max(start);
    if stop == start {
        stop = end;
    }
    if text[start..end].starts_with(REDACTED) {
        stop = stop.max(start + REDACTED.len());
    }
    spans.push(Span {
        start,
        end: stop,
        kind: SpanKind::QueryValue(placeholder),
        anchor: None,
    });
}

/// The URLs the 1.0.45 telemetry scrub re-serialised (its `URL_REGEX`), for [`empty_credential_key_spans`].
static URL_1045_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"https?://[^\s"'<>(){}\[\],;`]+"#));

/// What follows a URL that 1.0.45 re-serialised ending in `key=`: optional blanks, a quote, then an assignment value.
static NEXT_VALUE_REGEX: LazyLock<Regex> =
    LazyLock::new(|| compile(r#"\A\s*(["']?)([^\s"',&]{8,})"#));

/// u46 spans5 (found by the 100k differential run): through 1.0.45 the URL pass re-serialised a query whose last pair
/// has no value (`?a=1&db_password`, `?db_pass%77ord=`) as `...&db_password=`, so when that key (decoded) ends in a
/// credential name and is not a [`SENSITIVE_QUERY_PARAMS`] key (those got `=redacted`), the assignment rule read the
/// text after the URL, past blanks and an opening quote, as its value: `?a=1&db_password\nS3cretValue` lost
/// `S3cretValue`. Redact that value the same way (benign values kept). Linear: one URL scan, one parse per URL with a
/// query, an anchored match after each.
fn empty_credential_key_spans(input: &str, spans: &mut Vec<Span>) {
    for run in URL_1045_REGEX.find_iter(input) {
        if !run.as_str().contains('?') {
            continue;
        }
        let Ok(url) = url::Url::parse(run.as_str()) else {
            continue;
        };
        let Some((key, value)) = url
            .query()
            .and_then(|query| url::form_urlencoded::parse(query.as_bytes()).last())
        else {
            continue;
        };
        if !value.is_empty()
            || SENSITIVE_QUERY_PARAMS
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&key))
            || !CREDENTIAL_KEY_REGEX.is_match(&key)
        {
            continue;
        }
        let Some(c) = NEXT_VALUE_REGEX.captures(&input[run.end()..]) else {
            continue;
        };
        let (Some(quote), Some(next)) = (c.get(1), c.get(2)) else {
            continue;
        };
        if !assignment_value_is_benign(&key, next.as_str(), !quote.as_str().is_empty(), None) {
            spans.push(Span::secret(
                run.end() + next.start(),
                run.end() + next.end(),
            ));
        }
    }
}

/// The placeholder for a query key's value when the key (percent- and `+`-decoded, any case, as the `url` crate's
/// form decoding reads it) is sensitive: a listed name, or one the assignment rule reads as a credential name
/// ([`CREDENTIAL_KEY_REGEX`]). No length cap: the assignment rule has none on a name's prefix, and each key is a
/// separate stretch of the text, so the decoding stays linear overall.
fn sensitive_query_key(key: &str) -> Option<&'static str> {
    // The parser drops TAB/LF/CR before it decodes anything.
    let raw: Vec<u8> = key
        .bytes()
        .filter(|b| !matches!(b, b'\t' | b'\n' | b'\r'))
        .collect();
    if raw.is_empty() {
        return None;
    }
    let mut decoded = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (
            raw[i],
            raw.get(i + 1).copied().and_then(hex),
            raw.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                decoded.push((h * 16 + l) as u8);
                i += 3;
            }
            (b'+', _, _) => {
                decoded.push(b' ');
                i += 1;
            }
            (b, _, _) => {
                decoded.push(b);
                i += 1;
            }
        }
    }
    match SENSITIVE_QUERY_PARAMS
        .iter()
        .position(|s| s.as_bytes().eq_ignore_ascii_case(&decoded))
    {
        Some(i) if QUERY_KEY_USES_MARKER[i] => Some(REDACTED),
        Some(_) => Some(REDACTED_URL_VALUE),
        // Any other key the assignment rule reads as a credential name is written with the marker, as that rule writes
        // it (over-redacts a short or reference-shaped value, which the rule would have kept).
        None => CREDENTIAL_KEY_REGEX
            .is_match(&String::from_utf8_lossy(&decoded))
            .then_some(REDACTED),
    }
}

/// Test view of [`userinfo_removals`]: the text with only the userinfo removed.
#[cfg(test)]
fn strip_userinfo(text: &str) -> Cow<'_, str> {
    match userinfo_removals(text) {
        Some(removals) => apply_spans(text, removals),
        None => Cow::Owned(REDACTED.to_owned()),
    }
}

/// A text as the parser reads it for URL authorities, and every authority start in it (see [`userinfo_removals`] for
/// the rules); shared by [`userinfo_removals`] and [`keep_authority_ends`]. The caller has checked the text is under
/// 4 GiB.
struct AuthorityScan<'a> {
    /// The text without TAB/LF/CR.
    c: Cow<'a, [u8]>,
    /// Where `c[k]` sits in the text (empty when the two are the same).
    idx: Vec<u32>,
    /// (first byte of the authority in `c`, scheme is special, the scheme's `:` in `c`).
    starts: Vec<(usize, bool, usize)>,
}

impl AuthorityScan<'_> {
    /// Where `c[k]` sits in the text.
    fn at(&self, k: usize) -> usize {
        if self.idx.is_empty() {
            k
        } else {
            self.idx[k] as usize
        }
    }
}

fn authority_scan(raw: &[u8]) -> AuthorityScan<'_> {
    // `c`: the text without TAB/LF/CR; `idx[k]`: where `c[k]` sits in `raw` (empty when the two are the same).
    let ignored = |b: u8| matches!(b, b'\t' | b'\n' | b'\r');
    let mut idx: Vec<u32> = Vec::new();
    let cleaned: Cow<'_, [u8]> = if raw.iter().any(|&b| ignored(b)) {
        let mut v = Vec::with_capacity(raw.len());
        for (i, &b) in raw.iter().enumerate() {
            if !ignored(b) {
                v.push(b);
                idx.push(i as u32);
            }
        }
        Cow::Owned(v)
    } else {
        Cow::Borrowed(raw)
    };
    let c: &[u8] = &cleaned;
    let n = c.len();
    // A TAB, LF or CR sat right before `c[k]` in the original: it starts a word there (Fable r3 L3: `see\thttp:u:p@h`
    // is `http`, as well as `seehttp`).
    let break_before = |k: usize| k > 0 && !idx.is_empty() && idx[k] > idx[k - 1] + 1;
    let slash = |b: u8| matches!(b, b'/' | b'\\');

    // Authority starts: (first byte of the authority, scheme is special, the scheme's `:`).
    let mut starts: Vec<(usize, bool, usize)> = Vec::new();
    let mut token_starts: Vec<usize> = Vec::new();
    let mut k = 0;
    while k < n {
        if !is_scheme_byte(c[k]) {
            k += 1;
            continue;
        }
        token_starts.clear();
        let mut word_has_letter = false;
        while k < n && is_scheme_byte(c[k]) {
            if break_before(k) {
                word_has_letter = false;
            }
            if c[k].is_ascii_alphabetic() && !word_has_letter {
                word_has_letter = true;
                token_starts.push(k);
            }
            k += 1;
        }
        if k >= n || c[k] != b':' || token_starts.is_empty() {
            continue;
        }
        // A run broken by a line break holds several candidate tokens (`ht\ntps:` is `https` and `tps`); each kind
        // that occurs is read as the parser would read it, and the removals are merged.
        // A special scheme glued to the word before it (`prefixhttps:///alice:pw@host/`) is a non-special scheme to the
        // parser, but a URL pattern looking for `https://` finds it (1.0.45 did, u46 r8 M): when two slashes follow,
        // the longest special-scheme suffix is read as a scheme of its own too (over-redaction accepted). Without the
        // two slashes (`Makefile:3: error from git@host`) it is not.
        let glued_special = c
            .get(k + 1..k + 3)
            .is_some_and(|s| s.iter().all(|&b| slash(b)))
            && token_starts
                .iter()
                .any(|&t| special_scheme_suffix(&c[t..k]));
        if glued_special || token_starts.iter().any(|&t| is_special_scheme(&c[t..k])) {
            let mut s = k + 1;
            while s < n && slash(c[s]) {
                s += 1;
            }
            starts.push((s, true, k));
        }
        if token_starts.iter().any(|&t| !is_special_scheme(&c[t..k]))
            && c.get(k + 1..k + 3) == Some(b"//".as_slice())
        {
            starts.push((k + 3, false, k));
        }
    }
    AuthorityScan {
        c: cleaned,
        idx,
        starts,
    }
}

/// `next[i]`: the first byte at or after `i` of `c` that ends an authority (`n` when none): `/ \ ? #` after a special
/// scheme, `/ ? #` after any other.
fn next_terminators(c: &[u8], special: bool) -> Vec<u32> {
    let n = c.len();
    let mut next = vec![n as u32; n + 1];
    for i in (0..n).rev() {
        let ends = matches!(c[i], b'/' | b'?' | b'#') || (special && c[i] == b'\\');
        next[i] = if ends { i as u32 } else { next[i + 1] };
    }
    next
}

/// One rule for credentials in a URL authority, applied to the whole text whether or not the URL parses. It follows
/// the `url` crate's (WHATWG) reading, which is what a real client would send:
///
/// - the parser removes every TAB, LF and CR before it reads anything, so this scan works on the text with them left
///   out and maps the result back to the original bytes (u46 r3: LF/CR inside the authority no longer hide a
///   password, `postgres://alice:\ns3cret@db/`);
/// - a scheme token is `[A-Za-z][A-Za-z0-9+.-]*:` at a word boundary, case-insensitive; a TAB, LF or CR in the
///   original text also starts a word (as well as being ignored), and a token glued to leading digits or signs (`1http:`) starts at its first letter;
/// - after a special scheme (`http`, `https`, `ws`, `wss`, `ftp`, `file`) any run of `/` and `\` is skipped, zero
///   slashes included (`https:u:p@host`), and the authority ends at the first `/`, `\`, `?` or `#`;
/// - after any other scheme the authority exists only after two forward slashes and ends at the first `/`, `?` or
///   `#` (`mailto:a@b`, `npm:@scope/pkg`, `C:\proj\@types` and `git@host:org/repo` carry none);
/// - everything from the authority start through its LAST `@` is removed, whatever it contains (spaces, line breaks,
///   VT, FF, U+2028, NBSP, other non-ASCII and `\` are part of the userinfo: the parser percent-encodes them). A line
///   break does not end the authority, as for the parser: prose such as `https://example.com\nbob@example.org` loses
///   `example.com\nbob@`. That over-redaction is accepted (this scrub feeds telemetry and doctor output only).
///
/// One pass, linear in the text: the next terminator and the last `@` are tabulated once (u32 positions), so no
/// authority is scanned twice and there is no backtracking and no length cap. The one case where removing a userinfo
/// would leave a slash run that exposes the next authority (`https://a@//b:c@h`) is followed in the same pass (the
/// chain step below). Returns disjoint [`SpanKind::Remove`] ranges of the original text, each anchored at its scheme's
/// `:`; `None` only for a text of 4 GiB or more (the caller fails closed).
fn userinfo_removals(text: &str) -> Option<Vec<Span>> {
    let raw = text.as_bytes();
    if !(raw.contains(&b'@') && raw.contains(&b':')) {
        return Some(Vec::new());
    }
    if u32::try_from(raw.len()).is_err() {
        return None;
    }
    let AuthorityScan {
        c: cleaned,
        idx,
        starts,
    } = authority_scan(raw);
    let c: &[u8] = &cleaned;
    let n = c.len();
    let at = |k: usize| if idx.is_empty() { k } else { idx[k] as usize };
    let slash = |b: u8| matches!(b, b'/' | b'\\');
    if starts.is_empty() {
        return Some(Vec::new());
    }

    // next_special[i] / next_other[i]: first terminator at or after i, each built only when a start of its kind
    // exists; last_at[i]: the last `@` before i, or NONE.
    const NONE: u32 = u32::MAX;
    let next_special = if starts.iter().any(|&(_, special, _)| special) {
        next_terminators(c, true)
    } else {
        Vec::new()
    };
    let next_other = if starts.iter().any(|&(_, special, _)| !special) {
        next_terminators(c, false)
    } else {
        Vec::new()
    };
    let mut last_at = vec![NONE; n + 1];
    for i in 0..n {
        last_at[i + 1] = if c[i] == b'@' { i as u32 } else { last_at[i] };
    }

    let mut ranges: Vec<Span> = Vec::new();
    let mut chained = vec![false; n + 1];
    for (mut s, special, colon) in starts {
        loop {
            let end = if special {
                next_special[s]
            } else {
                next_other[s]
            } as usize;
            let a = last_at[end];
            if a == NONE || (a as usize) < s {
                break;
            }
            let a = a as usize;
            ranges.push(Span {
                start: at(s),
                end: at(a) + 1,
                kind: SpanKind::Remove,
                anchor: Some(at(colon)),
            });
            // Chain: `https://a@//b:c@h` -> removing `a@` leaves `https:///b:c@h`, whose authority is `b:c@h`.
            // Follow the skipped run now; each run is entered once, so the whole pass stays linear.
            if special && a + 1 == end && end < n && !chained[end] && slash(c[end]) {
                chained[end] = true;
                s = end;
                while s < n && slash(c[s]) {
                    s += 1;
                }
                continue;
            }
            break;
        }
    }
    // Disjoint: union the overlapping and touching ranges, each keeping the first one's anchor.
    ranges.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<Span> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    Some(merged)
}

fn is_scheme_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')
}

/// Whether `token` is one of the special schemes.
fn is_special_scheme(token: &[u8]) -> bool {
    ["http", "https", "ws", "wss", "ftp", "file"]
        .iter()
        .any(|s| token.eq_ignore_ascii_case(s.as_bytes()))
}

/// Whether `token` ends in a special scheme that something else comes before (`prefixhttps`, `xfile`).
fn special_scheme_suffix(token: &[u8]) -> bool {
    ["http", "https", "ws", "wss", "ftp", "file"]
        .iter()
        .any(|s| {
            token.len() > s.len()
                && token[token.len() - s.len()..].eq_ignore_ascii_case(s.as_bytes())
        })
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
            // An empty value holds nothing to hide; filling it would also make a second scrub change the text again.
            let value = if !v.is_empty()
                && v != REDACTED
                && SENSITIVE_QUERY_PARAMS
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

/// The redactor exactly as released in 1.0.45 (`f5a742ad`, `crates/codegen/fuigo-secrets/src/sanitizer.rs` without its
/// test module; rustfmt-formatted, nothing else changed), kept frozen so the differential test in `tests` can show
/// that nothing 1.0.45 removed survives the span redactor (u46 r8). Never edit it to make that test pass.
#[cfg(test)]
#[path = "sanitizer_1045_frozen.rs"]
#[allow(dead_code, clippy::all)]
mod frozen_1045;

#[cfg(test)]
mod tests {
    use super::*;

    /// `redact_secrets` with an empty credential registry. The registry is process-wide and the
    /// `sent_credentials` tests leave short values in it, so a shape test takes the registry lock and clears it
    /// first; otherwise it fails only when it happens to run after one of them.
    fn redact_secrets(input: &str) -> Cow<'_, str> {
        let _registry = crate::sent_credentials::REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::sent_credentials::clear_for_tests();
        super::redact_secrets(input)
    }

    /// If you add a regex to `MATCH_ANY`, also add a redaction pass in `redact_secrets` and update this count.
    #[test]
    fn match_any_count_matches_redact_secrets_passes() {
        assert_eq!(MATCH_ANY.patterns().len(), 15);
    }

    #[test]
    fn no_match_returns_borrowed() {
        assert!(matches!(
            redact_secrets("just a normal log line"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(redact_secrets("model=grok-3"), Cow::Borrowed(_)));
    }

    /// Joins fixture fragments at runtime so realistic-looking fake tokens never appear whole in the source text.
    /// Secret scanners (e.g. GitHub push protection) would otherwise flag them.
    fn fixture(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn redacts_known_secret_shapes() {
        let cases = [
            (
                fixture(&["key: fuigo-", "abc123XYZdef456GHIjkl789"]),
                "fuigo api key",
            ),
            (
                fixture(&["aws AKIA", "ABCDEFGHIJKLMNOP key"]),
                "aws access key",
            ),
            (
                fixture(&["Authorization: Bearer eyJhbGciOiJIUzI1NiJ9", ".foo.bar.baz"]),
                "bearer token",
            ),
            (fixture(&["api_key=", "ABCDEFGHIJ"]), "key=value"),
            (
                fixture(&["refresh_token: \"rt_", "abc1234567\""]),
                "compound token name",
            ),
            (
                fixture(&[
                    "deployment key eyJhbGciOiJIUzI1NiJ9",
                    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f",
                ]),
                "bare jwt without prefix",
            ),
        ];
        for (input, label) in cases {
            let out = redact_secrets(&input);
            assert!(out.contains("[REDACTED_SECRET]"), "{label}: {out:?}");
        }
    }

    /// Audit S11-F2: env-style names, JSON-quoted keys, `Basic` headers and more vendor token families.
    #[test]
    fn redacts_env_style_json_basic_and_more_vendor_tokens() {
        // (input, the secret value that must be gone, text that must be kept)
        let cases = [
            (
                "GITHUB_TOKEN=abcd1234efgh5678",
                "abcd1234efgh5678",
                "GITHUB_TOKEN=",
            ),
            (
                "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG",
                "wJalrXUtnFEMIK7MDENG",
                "export AWS_SECRET_ACCESS_KEY=",
            ),
            (
                "DB_PASSWORD=hunter2hunter2",
                "hunter2hunter2",
                "DB_PASSWORD=",
            ),
            (
                "db_password: \"hunter2hunter2\" # note",
                "hunter2hunter2",
                "# note",
            ),
            (
                "{\"password\": \"hunter2hunter2\", \"user\": \"bob\"}",
                "hunter2hunter2",
                "\"user\": \"bob\"",
            ),
            (
                "{\"api_key\":\"abcdefghijkl\",\"n\":1}",
                "abcdefghijkl",
                "\"n\":1",
            ),
            (
                "{'client_secret': 'abcdefghijkl'}",
                "abcdefghijkl",
                "client_secret",
            ),
            (
                "curl -H 'Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ=' x",
                "dXNlcjpwYXNzd29yZDEyMzQ=",
                "curl -H",
            ),
            (
                concat!("npm_token np", "m_0123456789abcdefghijABCDEFGHIJ012345 end"),
                concat!("np", "m_0123456789abcdefghijABCDEFGHIJ012345"),
                " end",
            ),
            (
                "hf_abcdefghijklmnopqrstuvwxyzABCD0123 end",
                "hf_abcdefghijklmnopqrstuvwxyzABCD0123",
                " end",
            ),
            (
                "SG.abcdefghijklmnop.abcdefghijklmnopqrst end",
                "SG.abcdefghijklmnop.abcdefghijklmnopqrst",
                " end",
            ),
            (
                "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef end",
                "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef",
                " end",
            ),
            // Fake fixtures, split so a host secret scanner does not read the source as a real token.
            (
                concat!("shp", "at_0123456789abcdef0123456789abcdef end"),
                concat!("shp", "at_0123456789abcdef0123456789abcdef"),
                " end",
            ),
            (
                "whsec_0123456789abcdefghijklmnop end",
                "whsec_0123456789abcdefghijklmnop",
                " end",
            ),
            (
                concat!("pk", "_live_0123456789abcdefghijklmn end"),
                concat!("pk", "_live_0123456789abcdefghijklmn"),
                " end",
            ),
            (
                concat!("rk_", "live_0123456789abcdefghijklmn end"),
                concat!("rk_", "live_0123456789abcdefghijklmn"),
                " end",
            ),
            (
                "gsk_0123456789abcdefghijklmnopqrstuvwxyz end",
                "gsk_0123456789abcdefghijklmnopqrstuvwxyz",
                " end",
            ),
            (
                "pypi-AgEIcHlwaS5vcmcAbcdefghijklmnop end",
                "pypi-AgEIcHlwaS5vcmcAbcdefghijklmnop",
                " end",
            ),
            (
                "ya29.a0AfH6SMBabcdefghijklmnopqrstuv end",
                "ya29.a0AfH6SMBabcdefghijklmnopqrstuv",
                " end",
            ),
            (
                "token xoxs-0123456789-abcdef end",
                "xoxs-0123456789-abcdef",
                " end",
            ),
        ];
        for (input, secret, kept) in cases {
            let out = redact_secrets(input);
            assert!(!out.contains(secret), "{input:?} leaked: {out:?}");
            assert!(out.contains("[REDACTED_SECRET]"), "{input:?}: {out:?}");
            assert!(out.contains(kept), "{input:?} lost {kept:?}: {out:?}");
        }
    }

    /// Audit S11-F2: the wider patterns leave ordinary code and prose alone.
    #[test]
    fn wider_patterns_keep_ordinary_text() {
        for input in [
            "let max_tokens = 4096;",
            "token_count = compute_token_count(input)",
            "tokenizer=bert-base-uncased-vocabulary",
            "primary_key: user_identifier_column",
            "monkey=banana",
            "api_key_header_name: x-api-key-header",
            "Basic authentication is required for this endpoint",
            "Basic Internationalization support for the endpoint",
            "the password field is shown",
            "hf_dataset_loader and shpat_ are prefixes",
            "ya29 is a prefix; SG.x.y is short; whsec_ too",
            "disk_usage=95% task_id=12345678 risk-assessment-document-final",
            "fn token(&self) -> Token { self.token.clone() }",
        ] {
            assert!(
                matches!(redact_secrets(input), Cow::Borrowed(_)),
                "{input:?} was rewritten: {:?}",
                redact_secrets(input)
            );
        }
    }

    /// Audit S11-F2: the assignment scan stays linear on long runs of identifier characters.
    #[test]
    fn assignment_scan_is_not_quadratic() {
        // Time the scrub itself, not the wait for the registry lock that other tests hold.
        let _registry = crate::sent_credentials::REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::sent_credentials::clear_for_tests();
        let long_run = format!("{} done\n", "a_".repeat(500_000));
        let many_keywords = format!("{}=", "token_".repeat(100_000));
        let start = std::time::Instant::now();
        assert!(matches!(super::redact_secrets(&long_run), Cow::Borrowed(_)));
        assert!(matches!(
            super::redact_secrets(&many_keywords),
            Cow::Borrowed(_)
        ));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn redacts_additional_provider_prefixes() {
        let cases = [
            (
                fixture(&["token ghp_", "0123456789abcdefghijABCDEFGHIJ012345"]),
                "github classic pat",
            ),
            (
                fixture(&[
                    "github_pat_",
                    "11ABCDE0123456789_abcdefghijklmnopqrstuvwxyz0123456789",
                ]),
                "github fine-grained pat",
            ),
            (
                fixture(&["glpat-", "0123456789abcdefABCD here"]),
                "gitlab pat",
            ),
            (
                fixture(&["xoxb-", "2420837490-2420837490-AbCdEfGhIjKlMnOpQr"]),
                "slack bot token",
            ),
            (
                fixture(&["xapp-1-", "A0123BCDEF-0123456789-abcdef0123"]),
                "slack app token",
            ),
            (
                fixture(&["AIza", "SyD0123456789abcdefghijklmnopqrstuvw"]),
                "google api key",
            ),
            (
                fixture(&["aws ASIA", "ABCDEFGHIJKLMNOP creds"]),
                "aws temporary access key",
            ),
            (
                fixture(&["stripe sk_live_", "0123456789abcdefghijABCD"]),
                "vendor sk_ key",
            ),
        ];
        for (input, label) in cases {
            let out = redact_secrets(&input);
            assert!(out.contains(REDACTED), "{label} not redacted: {out:?}");
        }
    }

    /// Review M1: a value that is a variable reference, a type, an identifier or a field access is not a secret,
    /// whatever the name; real values still redact.
    #[test]
    fn assignments_of_references_types_and_identifiers_are_not_secrets() {
        for input in [
            "GITHUB_TOKEN=$GITHUB_TOKEN",
            "NPM_TOKEN: ${{secrets.NPM_TOKEN}}",
            "auth_token: Option<String>,",
            "next_page_token = resp.next_page_token",
            "let csrf_token = generate_csrf_token(&session);",
            "self.session_token = response.session_token.clone();",
            "db_password = os.environ['DB_PASSWORD']",
            "\"token\": \"<your-token-here>\"",
            "export FUIGO_API_KEY=<paste-key-here>",
            "client_secret = ${CLIENT_SECRET}",
        ] {
            assert!(
                matches!(redact_secrets(input), Cow::Borrowed(_)),
                "{input:?} was rewritten: {:?}",
                redact_secrets(input)
            );
        }
    }

    /// Review R04 / S11-F2-R1: ordinary code and prose stay; token-shaped values, quoted literals and real Basic
    /// credentials still redact.
    #[test]
    fn code_after_credential_names_and_prose_after_basic_are_kept() {
        for input in [
            "let cancellation_token = CancellationToken::new();",
            "session_token = request.cookie(",
            "db_password = config.password",
            "db_password = request.body.password",
            "Authorization: Basic authentication is required",
            "{\"access_token\": \"eyJhbGciOi...\", \"expires_in\": 3600}",
        ] {
            assert!(
                matches!(redact_secrets(input), Cow::Borrowed(_)),
                "{input:?} -> {:?}",
                redact_secrets(input)
            );
        }
        for (input, secret) in [
            ("GITHUB_TOKEN=abcd1234efgh5678", "abcd1234efgh5678"),
            ("password = \"my_secret_password\"", "my_secret_password"),
            (
                "Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ=",
                "dXNlcjpwYXNzd29yZDEyMzQ=",
            ),
            ("Authorization: Basic Zm9vYmFyMTIz", "Zm9vYmFyMTIz"),
        ] {
            let out = redact_secrets(input);
            assert!(!out.contains(secret), "{input:?} leaked: {out:?}");
        }
    }

    /// Delta review (secret relaxation): only a value that is wholly a reference, a closed placeholder or code is kept;
    /// these realistic secrets merely start like one, and a letters-only Basic credential is not prose.
    #[test]
    fn values_that_only_look_like_references_or_code_still_redact() {
        for (input, secret) in [
            ("DB_PASSWORD=super_secret_password", "super_secret_password"),
            ("password: \"$ecureP@ss2024\"", "ecureP@ss2024"),
            ("password=$apr1$Kq3xZ9mB$Wf1kLd8pQ2rT6yVb0nXcE.", "Kq3xZ9mB"),
            ("secret = $argon2id$v=19$m=65536", "argon2id$v=19$m=65536"),
            ("api_key = $(curl_secret", "curl_secret"),
            ("token = <Zk3j9QxV7mPq2LwR", "Zk3j9QxV7mPq2LwR"),
            ("client_secret = ${NOT_CLOSED_abc123", "NOT_CLOSED_abc123"),
            (
                "Authorization: Basic ZmFrZVVzZXJGYWtlUGFzcw",
                "ZmFrZVVzZXJGYWtlUGFzcw",
            ),
            // Delta review D1: `user:pass` in Basic, and an unquoted literal password of words joined by `_`.
            ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
            (
                "db_password=correct_horse_battery_staple",
                "correct_horse_battery_staple",
            ),
        ] {
            let out = redact_secrets(input);
            assert!(!out.contains(secret), "{input:?} leaked: {out:?}");
        }
        // Wholly a reference or a closed `$(...)` stays.
        for input in [
            "TOKEN=$(read_token_from_vault)",
            "api_key = $API_KEY_FROM_ENV;",
        ] {
            assert!(
                matches!(redact_secrets(input), Cow::Borrowed(_)),
                "{input:?} -> {:?}",
                redact_secrets(input)
            );
        }
    }

    /// Delta review D2-05: a literal password of words joined by dots is not code, and a password is never shown cut
    /// short, so one ending in `...` is not a placeholder. Complete shell parameter expansions stay readable.
    #[test]
    fn dotted_and_ellipsis_passwords_redact_and_shell_references_stay() {
        for (input, secret) in [
            (
                "db_password=correct.horse.battery.staple",
                "correct.horse.battery.staple",
            ),
            // Grok u45 round 2: a single dot does not make two words code.
            ("password=correct.horse", "correct.horse"),
            // Review dfix5-4: a credential word inside a longer word (monkey, author) is not a credential part.
            ("password=monkey.business", "monkey.business"),
            ("db_password=author.name", "author.name"),
            // Delta review D3-06: a credential word inside the literal does not make it code after a password name.
            ("password=correct.horse.secret", "correct.horse.secret"),
            ("db_password=admin:secretpass", "admin:secretpass"),
            ("password=battery.staple.key", "battery.staple.key"),
            ("password = \"Tr0ub4dorAndMore...\"", "Tr0ub4dorAndMore"),
            ("\"password\": \"letmeinplease...\"", "letmeinplease"),
            ("DB_PASSWORD=hunter2hunter2...", "hunter2hunter2"),
        ] {
            let out = redact_secrets(input);
            assert!(!out.contains(secret), "{input:?} leaked: {out:?}");
        }
        for input in [
            "TOKEN=${TOKEN:-fallback}",
            "api_key = ${API_KEY:?missing}",
            "secret=${SECRET_VALUE:=}",
            "password=${DB_PASSWORD-unset}",
            "token=${#GITHUB_TOKEN}",
            "client_secret = ${CLIENT_SECRET%%suffix}",
            "db_password = config.password",
            "next_token = resp.next_page_token",
            "{\"access_token\": \"eyJhbGciOi...\", \"expires_in\": 3600}",
        ] {
            assert!(
                matches!(redact_secrets(input), Cow::Borrowed(_)),
                "{input:?} -> {:?}",
                redact_secrets(input)
            );
        }
    }

    #[test]
    fn real_assignment_values_still_redact() {
        for (input, secret) in [
            (
                concat!("GITHUB_TOKEN=gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
                "abcdefghijklmnop",
            ),
            ("api_key = Zk3j9QxV7mPq2LwR8sTn", "Zk3j9QxV7mPq2LwR8sTn"),
            (
                "auth_token: \"x8F2kQ9zLm4PvB7nR1sT\"",
                "x8F2kQ9zLm4PvB7nR1sT",
            ),
            (
                "password=correcthorsebatterystaple",
                "correcthorsebatterystaple",
            ),
            ("db_password = hunter2hunter2", "hunter2hunter2"),
            ("secret_key=AbCdEfGhIjKlMnOp", "AbCdEfGhIjKlMnOp"),
        ] {
            let out = redact_secrets(input);
            assert!(!out.contains(secret), "{input:?} leaked: {out:?}");
        }
    }

    #[test]
    fn does_not_over_redact_sk_lookalikes() {
        // `\b` anchor: a stray `sk-`/`sk_` mid-word must not fold the suffix.
        for input in [
            "task-deadbeefdeadbeefdeadbeef0123",
            "disk-0123456789abcdefghijklmno",
            "risk-0123456789abcdefghijklmno",
        ] {
            assert_eq!(redact_secrets(input), input, "over-redacted: {input}");
        }
    }

    /// The credential registry is process-wide and the `sent_credentials` tests record short values such as
    /// `abcdefgh`, leaving them behind. A shape test must not see them (it once saw `abcdefgh` inside a lookalike).
    #[test]
    fn shape_tests_do_not_see_credentials_left_by_registry_tests() {
        {
            let _registry = crate::sent_credentials::REGISTRY_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            crate::sent_credentials::record("abcdefgh");
        }
        let input = "disk-0123456789abcdefghijklmno";
        assert_eq!(redact_secrets(input), input, "registry leaked in: {input}");
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let input = "key:\n-----BEGIN PRIVATE KEY-----\nMIIabc123def456\nMIIxyz789\n-----END PRIVATE KEY-----\ndone";
        let out = redact_secrets(input);
        assert!(out.contains(REDACTED), "PEM not redacted: {out}");
        assert!(!out.contains("MIIabc123"), "PEM body leaked: {out}");
        assert!(
            !out.contains("BEGIN PRIVATE KEY"),
            "PEM header leaked: {out}"
        );
    }

    #[test]
    fn redacts_bare_jwt_leaving_no_token() {
        let out = redact_secrets(
            "deployment key eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f",
        );
        assert!(!out.contains("eyJ"), "bare JWT survived redaction: {out}");
    }

    #[test]
    fn redacts_sensitive_url_query_params() {
        let out = redact_secrets("callback https://x.ai/cb?code=ABC123XYZ&state=xyz789 failed");
        assert!(!out.contains("ABC123XYZ"), "OAuth code leaked: {out}");
        assert!(!out.contains("xyz789"), "state leaked: {out}");
    }

    #[test]
    fn url_regex_excludes_trailing_punctuation() {
        let out = redact_secrets("see `https://x.ai/cb?code=ABCD12345`");
        assert!(out.ends_with('`'), "trailing backtick lost: {out}");
    }

    #[test]
    fn leaves_unrelated_strings_alone() {
        let input = "https://api.example.com/v1/health?region=us-east-1";
        assert_eq!(redact_secrets(input), input);
    }

    #[test]
    fn redact_user_paths_collapses_home_and_username_segments() {
        let usernames = vec!["alice".to_owned()];
        let out = redact_user_paths_env(
            "/Users/alice/work/alice/file",
            Some("/Users/alice"),
            &usernames,
        );
        assert_eq!(out, "~/work/<user>/file");
    }

    #[test]
    fn redact_user_paths_home_prefix_matches_whole_segment_only() {
        // "/Users/bob" must not collapse inside "/Users/bobby".
        let out = redact_user_paths_env("/Users/bobby/x", Some("/Users/bob"), &[]);
        assert_eq!(out, "/Users/bobby/x");
    }

    #[test]
    fn redact_user_paths_collapses_home_and_username_before_punctuation() {
        let home = Some("/Users/alice");
        let cases = [
            ("open '/Users/alice'", "open '~'"),
            ("/Users/alice: permission denied", "~: permission denied"),
            ("/Users/alice, retrying", "~, retrying"),
            ("path /Users/alice ok", "path ~ ok"),
        ];
        for (input, want) in cases {
            assert_eq!(
                redact_user_paths_env(input, home, &[]),
                want,
                "input: {input}"
            );
        }
        assert_eq!(
            redact_user_paths_env("/data/alice: denied", None, &["alice".to_owned()]),
            "/data/<user>: denied"
        );
        // The longer `alicia` must not fold to the `alice` home
        assert_eq!(
            redact_user_paths_env("/Users/alicia/x", home, &[]),
            "/Users/alicia/x"
        );
    }

    #[test]
    fn redact_user_paths_backstop_anonymizes_when_env_unset() {
        let out = redact_user_paths_with_backstop("/Users/realname/secret/file", None, &[]);
        assert_eq!(out, "/Users/<user>/secret/file");
    }

    #[test]
    fn redact_user_paths_backstop_skipped_when_env_known() {
        // Regression guard: when env is known the regex backstop must NOT run.
        // The backstop *would* collapse `/Users/Shared`, so it must survive here.
        let out = redact_user_paths_with_backstop(
            "/Users/Shared/cfg",
            Some("/Users/alice"),
            &["alice".to_owned()],
        );
        assert_eq!(out, "/Users/Shared/cfg");
    }

    #[test]
    fn redact_url_strips_credentials_and_fragment() {
        let mut url = url::Url::parse(
            "https://user:pw@idp.example.com/cb?code=ABC123XYZ&page=2#access_token=DEF456",
        )
        .unwrap();
        redact_url(&mut url);
        let out = url.to_string();
        assert!(!out.contains("user"), "userinfo leaked: {out}");
        assert!(!out.contains("pw"), "password leaked: {out}");
        assert!(!out.contains("ABC123XYZ"), "OAuth code leaked: {out}");
        assert!(!out.contains("DEF456"), "fragment token leaked: {out}");
        assert!(out.contains("idp.example.com/cb"), "lost host/path: {out}");
        assert!(out.contains("page=2"), "lost benign param: {out}");
        assert!(
            !out.contains("%5B") && !out.contains("%5D"),
            "placeholder bracket-encoded: {out}"
        );
    }

    /// P113 r3: the archive's shape scrub replaces a key and leaves everything else byte for byte, URLs included.
    #[test]
    fn p113_credential_shapes_keep_ordinary_text_and_urls() {
        let key = format!("{}{}", "sk-proj-", "p113FakeShapeKey0aB1cD2eF3gH4iJ5");
        let text = format!("see https://Example.COM/a?code=1 and {key}.");
        assert_eq!(
            redact_credential_shapes(&text),
            "see https://Example.COM/a?code=1 and [REDACTED_SECRET]."
        );
        let ordinary = "task-0123456789abcdefghijklmn and https://Example.COM";
        assert!(matches!(
            redact_credential_shapes(ordinary),
            Cow::Borrowed(_)
        ));
    }

    /// P113 r3 (Astra r3 #6): a PEM block with no END line still loses its BEGIN line and base64 body; text after the
    /// body is kept.
    #[test]
    fn p113_torn_pem_block_is_redacted() {
        let torn = "log\n-----BEGIN RSA PRIVATE KEY-----\nMIIEp113FakeTornBody\nAbCd+/==\n\nafter";
        let out = redact_private_key_blocks(torn);
        assert_eq!(out, "log\n[REDACTED_SECRET]\n\nafter");
        // Astra r4 #2: the telemetry scrub keeps the unterminated BEGIN line, so Sentry's joined-fragment check still
        // sees the whole block.
        assert!(redact_secrets(torn).contains("-----BEGIN RSA PRIVATE KEY-----"));
        // Astra r4 #4: an indented body; #6: a following line that is not base64 is kept whole.
        let indented = "-----BEGIN PRIVATE KEY-----\n    MIIEp113FakeIndentedBody\n    QUJD==\nrequest failed: timeout";
        assert_eq!(
            redact_private_key_blocks(indented),
            "[REDACTED_SECRET]\nrequest failed: timeout"
        );
        assert!(opens_private_key_block("x -----BEGIN PRIVATE KEY-----"));
        assert!(!opens_private_key_block(
            "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----"
        ));
    }
    /// P120 (R113 r5 #3): a torn key body followed on its line by terminal colour codes is still a key body.
    #[test]
    fn p120_torn_pem_body_followed_by_colour_codes_is_redacted() {
        let torn = "log\n-----BEGIN PRIVATE KEY-----\nMIIEp120FakeBody0123456789abcdef\u{1b}[0m\nrequest failed: timeout";
        assert_eq!(
            redact_private_key_blocks(torn),
            "log\n[REDACTED_SECRET]\nrequest failed: timeout"
        );
        let coloured = "\u{1b}[31m-----BEGIN PRIVATE KEY-----\u{1b}[0m\nMIIEp120FakeBody0123456789abcdef\nrequest failed: timeout";
        let out = redact_private_key_blocks(coloured);
        assert!(!out.contains("p120FakeBody"), "{out}");
        assert!(out.ends_with("\nrequest failed: timeout"), "{out}");
        assert!(opens_private_key_block(
            "-----BEGIN PRIVATE KEY-----\u{1b}[0m"
        ));
        assert!(opens_private_key_block(
            "-----BEGIN PRIVATE KEY-----\nMIIEp120FakeBody0123456789abcdef\u{1b}[0m"
        ));
    }

    /// P120 (R113 r5 #4): a marker followed by ordinary text on its line does not open a block that a later string
    /// could belong to.
    #[test]
    fn p120_marker_followed_by_text_opens_no_block() {
        assert!(!opens_private_key_block(
            "see -----BEGIN PRIVATE KEY----- in the docs"
        ));
        assert!(!opens_private_key_block(
            "-----BEGIN PRIVATE KEY-----\nrequest failed: timeout"
        ));
        assert!(!opens_private_key_block(
            "-----BEGIN PRIVATE KEY-----\nMIIEp120FakeBody0123456789abcdef\nrequest failed"
        ));
        // The marker line itself is still redacted when text follows it on the line.
        assert!(
            !redact_private_key_blocks(
                "-----BEGIN PRIVATE KEY----- in the docs\nMIIEp120NotABody0123456789abcdef"
            )
            .contains("BEGIN")
        );
    }

    /// Found by the `sanitizer` fuzz target: a second scrub of already-scrubbed text changed it again. The URL pass cut
    /// the URL at the placeholder's `[`, saw a sensitive query parameter with an empty value, and filled it in.
    #[test]
    fn scrubbing_twice_changes_nothing_for_a_url_with_a_sensitive_query_value() {
        let once = redact_secrets("https://user:pass@example.com/path?token=abc&x=1").into_owned();
        assert_eq!(once, "https://example.com/path?token=[REDACTED_SECRET]&x=1");
        assert_eq!(redact_secrets(&once), once);
    }

    #[test]
    fn redact_url_leaves_an_empty_sensitive_value_empty() {
        let mut url = url::Url::parse("https://example.com/p?token=&x=1").unwrap();
        redact_url(&mut url);
        assert_eq!(url.as_str(), "https://example.com/p?token=&x=1");
        let mut url = url::Url::parse("https://example.com/p?token=abc").unwrap();
        redact_url(&mut url);
        assert_eq!(url.as_str(), "https://example.com/p?token=redacted");
    }

    /// Found by the `sanitizer` fuzz target: a URL the parser refuses kept its `user:password@` in the output.
    #[test]
    fn a_url_with_an_invalid_host_still_loses_its_credentials() {
        let once = redact_secrets("see https://user:pass\u{4}@bad\u{0}host/x?a=1 now").into_owned();
        assert!(!once.contains("user:pass"), "{once:?}");
        assert!(once.contains("bad\u{0}host/x?a=1"), "{once:?}");
        assert_eq!(redact_secrets(&once), once);
        assert_eq!(strip_userinfo("https://a:b@c@d/p"), "https://d/p");
        assert_eq!(strip_userinfo("https://h/p@q"), "https://h/p@q");
    }

    #[test]
    fn stripping_credentials_from_a_refused_url_reaches_a_fixed_point_in_one_pass() {
        let input = "x https://userIza\u{0}@//userIza. y";
        let once = redact_secrets(input).into_owned();
        assert!(!once.contains("userIza\u{0}"), "{once:?}");
        assert_eq!(redact_secrets(&once), once);
    }

    fn scrubbed(input: &str) -> String {
        let once = redact_secrets(input).into_owned();
        assert_eq!(
            redact_secrets(&once),
            once,
            "not a fixed point for {input:?}"
        );
        once
    }

    /// Found by the `sanitizer` fuzz target (crash-minimized-f2a534f6): extra slashes hid `user@` from the old scan.
    #[test]
    fn userinfo_after_extra_slashes_is_removed_even_when_the_url_is_invalid() {
        for input in [
            "http:///\u{4}@token=\u{0}u",
            "https:////user@host\u{0}x/p",
            "https://\\\\user:pw@bad\u{0}host/x",
        ] {
            let out = scrubbed(input);
            assert!(
                !out.contains("user") && !out.contains("pw") && !out.contains('@'),
                "{out:?}"
            );
        }
        assert_eq!(
            scrubbed("go https:////user@example.com/p now"),
            "go https:////example.com/p now"
        );
        assert_eq!(
            scrubbed("go https:\\\\user:pw@example.com/p now"),
            "go https:\\\\example.com/p now"
        );
    }

    #[test]
    fn userinfo_ends_at_the_last_at_sign_of_the_authority() {
        assert_eq!(
            scrubbed("https://user:pa@ss@host.example/p"),
            "https://host.example/p"
        );
        assert_eq!(
            scrubbed("https://user:pa@ss@bad\u{0}host/p"),
            "https://bad\u{0}host/p"
        );
        assert_eq!(
            scrubbed("https://u%40x:p%40w@host.example/p"),
            "https://host.example/p"
        );
        assert_eq!(
            scrubbed("https://user:pw@[::1]:8080/p"),
            "https://[::1]:8080/p"
        );
    }

    #[test]
    fn userinfo_before_ports_hosts_and_other_schemes_is_removed() {
        assert_eq!(
            scrubbed("https://u:p@host.example:8443/p"),
            "https://host.example:8443/p"
        );
        assert_eq!(scrubbed("ftp://u:p@host.example/p"), "ftp://host.example/p");
        assert_eq!(
            scrubbed("postgres://u:p@db.example:5432/x"),
            "postgres://db.example:5432/x"
        );
        assert_eq!(
            scrubbed("https://u:p@host.example?q=1"),
            "https://host.example?q=1"
        );
        assert_eq!(
            scrubbed("https://u:p@host.example#frag"),
            "https://host.example#redacted"
        );
    }

    #[test]
    fn a_windows_drive_path_with_an_at_sign_directory_is_unchanged() {
        for keep in [
            r"C:\\proj\\node_modules\\@types\\node\\index.d.ts",
            r"d:\\a\\@scope\\pkg",
        ] {
            assert_eq!(strip_userinfo(keep), keep);
        }
        assert_eq!(strip_userinfo(r"ftp:\\\\u:p@host\\x"), r"ftp:\\\\host\\x");
    }

    /// Review r1 (Grok High): the url parser ignores tab, newline and carriage return, so a password hidden behind
    /// one is still a password.
    #[test]
    fn userinfo_split_by_tab_or_newline_is_removed_like_the_parser_reads_it() {
        for text in [
            "https:\n//alice:s3cret@internal.example/a",
            "https://alice:s3cret\t@internal.example/x",
            "ht\ntps://alice:s3cret@internal.example/x",
            "https:/\r/alice:s3cret@internal.example/x",
        ] {
            let out = redact_secrets(text);
            assert!(!out.contains("s3cret"), "{text:?} -> {out:?}");
            assert!(!out.contains("alice"), "{text:?} -> {out:?}");
        }
        // The parser reads ` x` as a username (percent-encoded), so the old "stays" expectation was under-redaction.
        assert_eq!(scrubbed("see https:// x@y"), "see https://y");
    }

    #[test]
    fn an_at_sign_outside_an_authority_stays() {
        for keep in [
            "mail alice@example.com now",
            "mailto:alice@example.com",
            "clone git@github.com:org/repo.git",
            "https://host.example/p@q",
        ] {
            assert_eq!(scrubbed(keep), keep);
        }
    }

    #[test]
    fn removing_one_userinfo_cannot_expose_another_on_a_second_pass() {
        let out = scrubbed("ab://x@y://z@w/p http://a@http://b@c/p");
        assert!(!out.contains('@'), "{out:?}");
    }

    /// Review r2 (Astra H2): the rule follows the parser, so slashless special schemes, upper case, spaces and
    /// non-ASCII inside the password, and TAB/LF/CR anywhere all lose their credentials.
    #[test]
    fn userinfo_is_removed_wherever_the_parser_finds_it() {
        for (text, want) in [
            ("https:alice:s3cret@example.com", "https:example.com"),
            ("HTTPS://alice:se cret@example.com", "HTTPS://example.com"),
            (
                "https://alice:pass\u{a0}word@example.com/x",
                "https://example.com/x",
            ),
            (
                "https://alice:p\u{e9}ss\u{1f511}@example.com/x",
                "https://example.com/x",
            ),
            (
                "https:\n//alice:s3cret@internal.example/a",
                "https:\n//internal.example/a",
            ),
            (
                "https://alice:s3cret\t@internal.example/x",
                "https://internal.example/x",
            ),
            ("ftp://u:p@h", "ftp://h"),
            ("WSS:\\\\u:p@h\\x", "WSS:\\\\h\\x"),
            ("1http://u:pw@h/x", "1http://h/x"),
            ("ab://u:p\\w@h/x", "ab://h/x"),
            ("https://a@//b:c@h/x", "https:////h/x"),
            ("http:u@//x:y@z/p", "http://z/p"),
            ("postgres://admin:my pass@db", "postgres://db"),
            ("postgres://admin:my\u{b}pass@db", "postgres://db"),
            ("postgres://admin:my\u{c}pass@db", "postgres://db"),
            ("postgres://admin:my\u{2028}pass@db", "postgres://db"),
            ("postgres://admin:my\u{a0}pass@db", "postgres://db"),
            ("ab://\nu:p@h/x", "ab://\nh/x"),
            ("https://a@\nb:c@h/x", "https://h/x"),
            (
                "postgres://alice:\ns3cret@db.example/",
                "postgres://db.example/",
            ),
            (
                "postgres://alice:\r\ns3cret@db.example/",
                "postgres://db.example/",
            ),
            ("https://alice\n:s3cret\r@h/x", "https://h/x"),
            ("see\thttp:alice:s3cret@h/x", "see\thttp:h/x"),
        ] {
            assert_eq!(strip_userinfo(text), want, "{text:?}");
            let out = redact_secrets(text);
            for secret in ["alice", "s3cret", "cret", "word", "pw", "u:p"] {
                assert!(!out.contains(secret), "{text:?} -> {out:?}");
            }
        }
    }

    /// u46 r3 (Astra r3 H3): a line break no longer ends the authority, as for the parser, which reads
    /// `example.combob` as the username of the first URL. The second line's userinfo-shaped prefix goes with it: this
    /// over-redaction (r2 kept these unchanged, under-redacting `postgres://alice:\ns3cret@db/`) is accepted, the
    /// scrub feeds telemetry and doctor output only. A backslash still ends a special authority.
    #[test]
    fn a_line_break_inside_the_authority_does_not_end_it() {
        for (text, want) in [
            (
                "https://example.com\nbob@example.org",
                "https://example.org",
            ),
            (
                "https://example.com\rbob@example.org",
                "https://example.org",
            ),
            ("ab://host\nbob@example.org", "ab://example.org"),
            (
                "https://example.com\tbob@example.org",
                "https://example.org",
            ),
        ] {
            assert_eq!(strip_userinfo(text), want, "{text:?}");
        }
        assert_eq!(
            strip_userinfo("https://host\\path@x"),
            "https://host\\path@x"
        );
    }

    #[test]
    fn a_url_with_an_upper_case_scheme_has_its_query_secrets_redacted() {
        let out = scrubbed("HTTPS://h/?token=x");
        assert!(!out.contains("token=x"), "{out:?}");
        assert!(out.contains("[REDACTED_SECRET]"), "{out:?}");
    }

    #[test]
    fn text_without_an_authority_is_byte_identical() {
        for keep in [
            "alice@x.com",
            "Contact: alice@x.com",
            "git@host:org/repo",
            "mailto:a@b",
            "npm:@scope/pkg",
            r"C:\Users\me\@types",
            r"C:\\proj\\node_modules\\@types\\node\\index.d.ts",
            "a:b@c",
            "registry:5000/img@sha256:abc",
            "https://npm.com/@scope/pkg",
        ] {
            assert_eq!(strip_userinfo(keep), keep, "{keep:?}");
            assert_eq!(scrubbed(keep), keep, "{keep:?}");
        }
    }

    /// The old regex backtracked: a long run of scheme-like tokens and `@` was the shape that costs it most. u46 spans:
    /// the whole scrub, query scan, assignment and span merge included, on 1 MiB shapes that would be quadratic for a
    /// rescan per span (`?token=` nested in values, overlapping removals, a value per pair). The 200 ms budget holds
    /// for an optimised build (`cargo test --release`, slowest shape about 95 ms); an unoptimised build sharing the CPU
    /// with the other tests is only held to 30 s, which still fails any quadratic path (hours at this size).
    #[test]
    fn a_one_mib_adversarial_input_is_scanned_in_linear_time() {
        let budget =
            std::time::Duration::from_millis(if cfg!(debug_assertions) { 30_000 } else { 200 });
        let mut texts = vec![
            "a:".repeat(512 * 1024),
            "a:@".repeat(350 * 1024),
            "http:@/".repeat(150 * 1024),
            "ab://x@".repeat(150 * 1024),
            "http://".repeat(150 * 1024) + "u@",
            "h:?token=".repeat(110 * 1024),
            "https://h/?code=x".repeat(60 * 1024),
            "a:?&code=x&".repeat(95 * 1024),
            "TOKEN=https://u:p@h\n".repeat(50 * 1024),
            "API=https://h\nDB_PASSWORD=p@ss1234\n".repeat(28 * 1024),
            format!("h:?code={}", "?code=a".repeat(150 * 1024)),
            format!("h:{}{}", "?code=".repeat(80 * 1024), ".".repeat(80 * 1024)),
            format!("h:#{}", ".\t".repeat(256 * 1024)),
            format!("h:?{}", "co\nde".repeat(100 * 1024)),
            "password=".repeat(110 * 1024),
        ];
        texts.push(format!(
            "{}{}",
            "a:".repeat(256 * 1024),
            "@".repeat(512 * 1024)
        ));
        for text in texts {
            let began = std::time::Instant::now();
            let out = strip_userinfo(&text);
            let took = began.elapsed();
            assert!(out.len() <= text.len());
            assert!(took < budget, "{took:?} for {} bytes", text.len());
            let began = std::time::Instant::now();
            let out = super::redact_secrets(&text);
            let took = began.elapsed();
            assert!(out.len() <= text.len() * 4 + 256);
            assert!(
                took < budget,
                "redact_secrets: {took:?} for {} bytes of {:?}",
                text.len(),
                &text[..24]
            );
        }
    }

    /// u46 r7 (Astra): TAB/LF/CR inside a query no longer end it (the parser drops them), an opaque fragment of a
    /// hierarchical URL is redacted whole again (as through 1.0.45), and n open values over n trailing dots are linear.
    #[test]
    fn r7_control_characters_fragments_and_trailing_dots() {
        let secret = concat!("OAuth", "Secret987");
        let mut failures = Vec::new();
        for (input, want) in [
            (
                format!("https://h/?x=1\t&code={secret}"),
                "https://h/?x=1\t&code=redacted".to_owned(),
            ),
            (
                format!("https://h/?x=1\n&code={secret}"),
                "https://h/?x=1\n&code=redacted".to_owned(),
            ),
            (
                format!("https://h/?x=1\r&code={secret}"),
                "https://h/?x=1\r&code=redacted".to_owned(),
            ),
            (
                format!("see https://h/?x=1\r\n&co\tde={secret} now"),
                "see https://h/?x=1\r\n&co\tde=redacted now".to_owned(),
            ),
            (
                format!("https://h/?to%6\nBen={secret}\n"),
                "https://h/?to%6\nBen=[REDACTED_SECRET]\n".to_owned(),
            ),
            (
                format!("ht\ttps://h/?code=Sec\nret{secret}, more"),
                "ht\ttps://h/?code=redacted, more".to_owned(),
            ),
            // A normal space still ends the URL.
            (
                format!("https://h/?x=1 &code={secret}"),
                format!("https://h/?x=1 &code={secret}"),
            ),
            (
                format!("https://h/#{secret}"),
                "https://h/#redacted".to_owned(),
            ),
            (
                format!("https://h#{secret}"),
                "https://h#redacted".to_owned(),
            ),
            (
                format!("(see https://h/x#{secret})."),
                "(see https://h/x#redacted).".to_owned(),
            ),
            (format!("HTTPS:h#{secret}"), "HTTPS:h#redacted".to_owned()),
            (
                format!("myapp://cb#{secret}"),
                "myapp://cb#redacted".to_owned(),
            ),
            (
                format!("postgres:\n//db/#{secret}"),
                "postgres:\n//db/#redacted".to_owned(),
            ),
            (
                format!("https://h/#{secret}\n\t next"),
                "https://h/#redacted\n\t next".to_owned(),
            ),
            // The parser reads the next line's first word into the fragment, and so does the scrub.
            (
                format!("https://h/#{secret}\nnext line"),
                "https://h/#redacted line".to_owned(),
            ),
            (
                format!("https://h/cb#state=x&access_token={secret}"),
                "https://h/cb#[REDACTED_SECRET]".to_owned(),
            ),
            (
                format!("https://h/?code={secret}#frag tail"),
                "https://h/?code=redacted tail".to_owned(),
            ),
            // A docs link keeps no marker (`fuigo-memory` counts markers).
            (
                "Docs: https://example.com/guide#overview".to_owned(),
                "Docs: https://example.com/guide#redacted".to_owned(),
            ),
            // Not hierarchical: only secret keys of the fragment go.
            (
                format!("mailto:a@b.example#x&token={secret}"),
                "mailto:a@b.example#x&token=[REDACTED_SECRET]".to_owned(),
            ),
            (
                "std::vec::Vec#push and localhost:8080#/route".to_owned(),
                "std::vec::Vec#push and localhost:8080#/route".to_owned(),
            ),
            (
                "https://h/# and https://h/#).".to_owned(),
                "https://h/# and https://h/#).".to_owned(),
            ),
        ] {
            let out = redact_secrets(&input).into_owned();
            if out != want {
                failures.push(format!("{input:?} -> {out:?}, want {want:?}"));
            } else if redact_secrets(&out) != out {
                failures.push(format!("NOT A FIXED POINT: {input:?} -> {out:?}"));
            }
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }

    /// u46 r7 Medium: `"h:" + "?code=" * n + "." * n` closed n values that each trimmed the same n dots. Release
    /// builds must finish n = 200_000 within 200 ms; debug builds are held to 30 s, which still fails a quadratic scan
    /// (4 * 10^10 steps).
    #[test]
    fn many_open_values_over_trailing_dots_are_linear() {
        let n = 200_000;
        let text = format!("h:{}{}", "?code=".repeat(n), ".".repeat(n));
        let budget =
            std::time::Duration::from_millis(if cfg!(debug_assertions) { 30_000 } else { 200 });
        let began = std::time::Instant::now();
        let out = super::redact_secrets(&text);
        let took = began.elapsed();
        assert!(took < budget, "{took:?} for n = {n}");
        assert!(
            out.len() < text.len() && !out.contains("?code=?"),
            "values redacted"
        );
    }

    /// What the parser reads as userinfo in `s` (percent-decoded and raw), as the strings to look for. Empty if `s`
    /// is not a URL or has none.
    fn parsed_credentials(s: &str) -> Vec<String> {
        let Ok(url) = url::Url::parse(s) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for enc in [Some(url.username()), url.password()].into_iter().flatten() {
            found.push(enc.to_owned());
            found.push(percent_decode(enc));
        }
        found
    }

    fn percent_decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
            {
                out.push((h * 16 + l) as u8);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Differential property (also in `fuzz/fuzz_targets/sanitizer.rs`): if the parser reads a username or password of
    /// three or more characters out of the text, or out of a suffix that starts at a letter, that credential followed
    /// by its delimiter must not survive when it occurs once in the text.
    fn assert_no_parsed_credential_survives(input: &str) {
        // u46 r3: the parser ignores TAB, LF and CR anywhere, and so does the scrub; no exception for line breaks.
        let strip = |t: &str| t.replace(['\t', '\n', '\r'], "");
        let out = strip(&redact_secrets(input));
        let flat = strip(input);
        let word_start = |i: usize| {
            input[..i]
                .chars()
                .rev()
                .filter(|ch| *ch != '\t')
                .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '.' | '-'))
                .all(|ch| !ch.is_ascii_alphabetic())
        };
        let starts = std::iter::once(0).chain(
            input
                .char_indices()
                .filter(|(i, ch)| ch.is_ascii_alphabetic() && word_start(*i))
                .map(|(i, _)| i),
        );
        for i in starts {
            for cred in parsed_credentials(&input[i..]) {
                if cred.chars().count() < 3 {
                    continue;
                }
                for delim in ["@", ":"] {
                    let needle = format!("{cred}{delim}");
                    if flat.matches(&needle).count() == 1 && flat.contains(&format!("{cred}@")) {
                        assert!(
                            !out.contains(&needle),
                            "{cred:?} survived in {out:?} for {input:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_parser_found_credentials_never_survive_100k_generated_inputs() {
        const PIECES: &[&str] = &[
            "http", "HTTPS", "ftp", "Ws", "file", "x", "ab", "a1.b", "1http", "ht\ntps", ":",
            "://", ":\\\\", ":/", ":\n//", "/", "\\", "\t", "\r", " ", "\u{a0}", "alice", "s3cret",
            "se cret", "p\u{e9}w", "@", "@@", "?", "#", ".example", "h", "%40x", "user", ":::",
            "[::1]", ":8080", "x@y.com", "\n",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..100_000 {
            let len = 2 + (next() % 11) as usize;
            let input: String = (0..len)
                .map(|_| PIECES[(next() % PIECES.len() as u64) as usize])
                .collect();
            assert_no_parsed_credential_survives(&input);
        }
    }

    /// u46 r5: the early assignment pass inserts the marker mid-query; the URL pass must still scrub what follows it.
    #[test]
    fn query_after_an_inserted_marker_is_still_scrubbed() {
        let clean = |s: &str| redact_secrets(s).into_owned();
        let out = clean("https://example.com/?token=abcdefgh123&code=OAuthSecret987");
        assert!(
            !out.contains("OAuthSecret987") && !out.contains("abcdefgh123"),
            "{out:?}"
        );
        let out = clean("https://example.com/?code=Xsecret99&token=Ysecret99");
        assert!(
            !out.contains("Xsecret99") && !out.contains("Ysecret99"),
            "{out:?}"
        );
        let out = clean("https://example.com/?a=1&password=Z&b=2");
        assert!(
            !out.contains("password=Z") && out.contains("a=1") && out.contains("b=2"),
            "{out:?}"
        );
        let out = clean("https://example.com/p?token=abcdefgh123&state=Zstate77#frag-secret");
        assert!(
            !out.contains("Zstate77") && !out.contains("abcdefgh123"),
            "{out:?}"
        );
        assert_eq!(clean(&out), out, "not idempotent");
        let out = clean("https://example.com/?token=abcdefgh123&x=1#api_key=Qfrag12345");
        assert!(!out.contains("abcdefgh123"), "{out:?}");
        let out =
            clean("see https://example.com/?token=abcdefgh123&code=OAuthSecret987, then more");
        assert!(
            !out.contains("OAuthSecret987") && out.contains(", then more"),
            "{out:?}"
        );
    }

    /// u46 r5 property: a query value of six or more characters under a secret key, as the `url` crate reads it, never
    /// survives, with or without the marker an earlier pass inserted before it.
    #[test]
    fn parsed_sensitive_query_values_never_survive_100k_generated_inputs() {
        const KEYS: &[&str] = &[
            "token", "code", "password", "api_key", "state", "key", "a", "b",
        ];
        const VALS: &[&str] = &[
            "abcdefgh123",
            "OAuthSecret987",
            "Zq9xk2m",
            "s3cr3t-v",
            "1",
            "ab",
            "[REDACTED_SECRET]",
            "x%20yzzzz",
        ];
        const TAILS: &[&str] = &["", "#frag", "#k=v", ",", " tail", "/", "\n"];
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..100_000 {
            let n = 1 + (next() % 4) as usize;
            let mut input = String::from("https://example.com/p?");
            for i in 0..n {
                if i > 0 {
                    input.push('&');
                }
                input.push_str(KEYS[(next() % KEYS.len() as u64) as usize]);
                input.push('=');
                input.push_str(VALS[(next() % VALS.len() as u64) as usize]);
            }
            input.push_str(TAILS[(next() % TAILS.len() as u64) as usize]);
            let out = redact_secrets(&input).into_owned();
            let cut: String = input
                .chars()
                .take_while(|c| !c.is_whitespace() && !"\"'<>(){},;`#".contains(*c))
                .collect();
            let cut = cut.replace("[REDACTED_SECRET]", "REDACTEDMARK");
            let Ok(url) = url::Url::parse(&cut) else {
                continue;
            };
            for (k, v) in url.query_pairs() {
                let sensitive = SENSITIVE_QUERY_PARAMS
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&k));
                if sensitive
                    && v.chars().count() >= 6
                    && v != "REDACTEDMARK"
                    && input.matches(&*v).count() == 1
                {
                    assert!(
                        !out.contains(&*v),
                        "{v:?} survived in {out:?} for {input:?}"
                    );
                }
            }
        }
    }

    /// u46 r4 H1: a path-less URL line before an assignment line must not cost the assignment its key name.
    #[test]
    fn assignment_after_a_pathless_url_line_is_redacted() {
        let pw = concat!("p@ss", "w0rd!23");
        for (input, expect) in [
            (
                format!("API=https://api.example.com\nDB_PASSWORD={pw}"),
                "DB_PASSWORD=[REDACTED_SECRET]",
            ),
            (
                format!("API=https://api.example.com\nTOKEN={pw}"),
                "TOKEN=[REDACTED_SECRET]",
            ),
            (
                format!("API=https://api.example.com\nexport SECRET={pw}"),
                "export SECRET=[REDACTED_SECRET]",
            ),
            (
                format!("see http:\n{{\"db_password\": \"{pw}\"}}"),
                "[REDACTED_SECRET]",
            ),
            (
                format!("API=https://api.example.com\nAPI_KEY: {pw}"),
                "API_KEY: [REDACTED_SECRET]",
            ),
        ] {
            let out = redact_secrets(&input).into_owned();
            assert!(out.contains(expect), "{input:?} -> {out:?}");
            assert!(
                !out.contains("w0rd!23") && !out.contains("p@ss"),
                "{input:?} -> {out:?}"
            );
        }
    }

    /// u46 r4 H1 invariant: a line the assignment pass redacts in isolation stays redacted when text, a URL
    /// included, and a line feed come before it.
    #[test]
    fn redacted_assignment_survives_any_prefix() {
        let pw = concat!("p@ss", "w0rd!23");
        let lines = [
            format!("DB_PASSWORD={pw}"),
            format!("export TOKEN={pw}"),
            format!("API_KEY={pw}"),
        ];
        let prefixes = [
            "",
            "x",
            "API=https://h",
            "http:",
            "https://a.b",
            "ftp:\\\\",
            "a://b",
            "see https:",
            "// ",
            "ws:",
            "http://u",
            "git@h",
            "//",
            "\\",
            "?",
        ];
        for line in &lines {
            let alone = redact_secrets(line).into_owned();
            assert!(alone.contains("[REDACTED_SECRET]"), "{line:?} -> {alone:?}");
            for prefix in prefixes {
                for sep in ["\n", "\r\n"] {
                    let out = redact_secrets(&format!("{prefix}{sep}{line}")).into_owned();
                    assert!(
                        out.ends_with(&alone),
                        "{prefix:?}{sep:?}{line:?} -> {out:?}"
                    );
                    assert!(
                        !out.contains("w0rd!23"),
                        "{prefix:?}{sep:?}{line:?} -> {out:?}"
                    );
                }
            }
        }
    }

    /// u46 spans: every case the review rounds named (r1 Grok item 2, r2 Astra H2, r3 Astra H3, r4 Fable H1, r5 Astra,
    /// r6 Astra H1/H2). Each detector reads the original text, so no rewrite can hide a later secret. Every output is a
    /// fixed point.
    #[test]
    fn every_reviewed_leak_is_closed_on_spans() {
        let pw = concat!("p@ss", "w0rd!23");
        let mut failures = Vec::new();
        for (input, want) in [
            // r6 H1: the assignment value ends at `&`; the URL's `code` is still scrubbed.
            (
                "TOKEN=https://example.com/?x=1&code=OAuthSecret987".to_owned(),
                "TOKEN=[REDACTED_SECRET]&code=redacted".to_owned(),
            ),
            // r6 H2: IPv6 hosts.
            (
                "https://[::1]/?code=OAuthSecret987".to_owned(),
                "https://[::1]/?code=redacted".to_owned(),
            ),
            (
                "HTTPS://[::1]:8443/?Code=OAuthSecret987".to_owned(),
                "HTTPS://[::1]:8443/?Code=redacted".to_owned(),
            ),
            // r5: a value after a redacted one.
            (
                "https://example.com/?token=abcdefgh123&code=OAuthSecret987".to_owned(),
                "https://example.com/?token=[REDACTED_SECRET]&code=redacted".to_owned(),
            ),
            // r4 H1: the key name on the next line is kept and its value redacted.
            (
                format!("API=https://api.example.com\nDB_PASSWORD={pw}"),
                "API=https://\nDB_PASSWORD=[REDACTED_SECRET]".to_owned(),
            ),
            (
                format!("API=https://api.example.com\r\nexport SECRET={pw}"),
                "API=https://\r\nexport SECRET=[REDACTED_SECRET]".to_owned(),
            ),
            // r3 H3, r2 H2, r1 item 2: what the parser reads as userinfo.
            (
                "postgres://alice:\ns3cret@db.example/".to_owned(),
                "postgres://db.example/".to_owned(),
            ),
            (
                "https:alice:s3cret@example.com".to_owned(),
                "https:example.com".to_owned(),
            ),
            (
                "HTTPS://alice:se cret@example.com".to_owned(),
                "HTTPS://example.com".to_owned(),
            ),
            (
                "https://alice:se\u{a0}cret@example.com/x".to_owned(),
                "https://example.com/x".to_owned(),
            ),
            (
                "postgres://alice:s3\u{b}cret@db".to_owned(),
                "postgres://db".to_owned(),
            ),
            (
                "postgres://alice:s3\u{c}cret@db".to_owned(),
                "postgres://db".to_owned(),
            ),
            (
                "postgres://alice:s3\u{2028}cret@db".to_owned(),
                "postgres://db".to_owned(),
            ),
            (
                "https:\n//alice:s3cret@internal.example/a".to_owned(),
                "https:\n//internal.example/a".to_owned(),
            ),
            (
                "https://alice:s3cret\t@internal.example/x".to_owned(),
                "https://internal.example/x".to_owned(),
            ),
            ("ftp://u:p@h".to_owned(), "ftp://h".to_owned()),
            (
                "HTTPS://h/?token=x".to_owned(),
                "HTTPS://h/?token=[REDACTED_SECRET]".to_owned(),
            ),
            (
                "password=correct.horse.secret".to_owned(),
                "password=[REDACTED_SECRET]".to_owned(),
            ),
            // Any scheme the parser reads a query for, fragments, and a URL nested in a value.
            (
                "postgres://db.example/app?password=Secret123x&sslmode=require".to_owned(),
                "postgres://db.example/app?password=[REDACTED_SECRET]&sslmode=require".to_owned(),
            ),
            (
                "https://h/cb#access_token=FragSecret99&state=xyz12345&x=1".to_owned(),
                "https://h/cb#[REDACTED_SECRET]".to_owned(),
            ),
            (
                "https://h/?next=https://x/?token=NestedSecret1".to_owned(),
                "https://h/?next=https://x/?token=[REDACTED_SECRET]".to_owned(),
            ),
            (
                "(see https://h/?code=OAuthSecret987).".to_owned(),
                "(see https://h/?code=redacted).".to_owned(),
            ),
            (
                "TOKEN=https://u:p@h/x".to_owned(),
                "TOKEN=[REDACTED_SECRET]".to_owned(),
            ),
            // Marker forgery: a marker already in the text unmasks nothing and hides nothing.
            (
                "https://h/?token=[REDACTED_SECRET]&code=OAuthSecret987".to_owned(),
                "https://h/?token=[REDACTED_SECRET]&code=redacted".to_owned(),
            ),
            (
                "https://h/?code=[REDACTED_SECRET]OAuthSecret987".to_owned(),
                "https://h/?code=redacted".to_owned(),
            ),
            (
                "https://[REDACTED_SECRET]:s3cretpw@h/".to_owned(),
                "https://h/".to_owned(),
            ),
        ] {
            let out = redact_secrets(&input).into_owned();
            let leaked: Vec<&str> = [
                "cret",
                "alice",
                "w0rd",
                "abcdefgh123",
                "OAuth",
                "horse",
                "u:p",
            ]
            .into_iter()
            .filter(|secret| input.contains(secret) && out.contains(secret))
            .collect();
            if !leaked.is_empty() {
                failures.push(format!("LEAK {leaked:?}: {input:?} -> {out:?}"));
            } else if out != want {
                failures.push(format!("FORMAT: {input:?} -> {out:?}, want {want:?}"));
            } else if redact_secrets(&out) != out {
                failures.push(format!("NOT A FIXED POINT: {input:?} -> {out:?}"));
            }
        }
        for keep in [
            "mail alice@example.com now",
            "git@host:org/repo",
            "clone git@github.com:org/repo.git",
            "mailto:alice@example.com",
            "npm:@scope/pkg",
            r"C:\Users\me\@types",
            r"C:\\proj\\node_modules\\@types\\node\\index.d.ts",
            r#"{"path": "C:\\proj\\node_modules\\@types\\node"}"#,
            "registry:5000/img@sha256:abc",
            "https://npm.com/@scope/pkg",
            "TOKEN=[REDACTED_SECRET]",
            "https://h/?token=[REDACTED_SECRET]",
            "https://h/?code=redacted",
            "see https://h/?code= and https://h/?token=",
        ] {
            let out = redact_secrets(keep);
            if out != keep {
                failures.push(format!("CHANGED: {keep:?} -> {out:?}"));
            }
        }
        assert!(failures.is_empty(), "\n{}", failures.join("\n"));
    }

    /// The query values the oracle treats as secret: its own copy of the list, so a change on one side shows.
    const ORACLE_SECRET_KEYS: [&str; 16] = [
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

    /// One complete URL, built part by part (scheme, optional userinfo, host, path, optional query and fragment), so
    /// the oracle knows where it ends without any boundary rule of its own (u46 r7: the previous window oracle copied
    /// the sanitizer's whitespace cutoff and so missed `?x=1<TAB>&code=`). TAB, LF and CR are dropped in at random
    /// places, as the parser ignores them; nothing else that ends a URL in text (a space, a quote, `<`, `>`, a
    /// backtick) is ever inside. `serial` makes every secret-looking piece unique.
    fn generated_url(next: &mut impl FnMut() -> u64, serial: &mut u32) -> String {
        const SCHEMES: &[&str] = &[
            "https://",
            "HTTPS://",
            "http://",
            "https:",
            "https:/",
            "ftp://",
            "ws://",
            "postgres://",
            "myapp://",
            "Ab+c.d-e://",
        ];
        const HOSTS: &[&str] = &["h", "example.com", "[::1]", "[::1]:8443", "10.0.0.1:5432"];
        const PATHS: &[&str] = &["", "/", "/cb", "/a/b.txt", "/v1/", "/%7Eme"];
        const KEYS: &[&str] = &[
            "token",
            "code",
            "password",
            "api_key",
            "state",
            "Code",
            "to%6Ben",
            "id_token",
            "access_token",
            "a",
            "page",
            "next",
        ];
        fn pick(next: &mut impl FnMut() -> u64, list: &[&'static str]) -> &'static str {
            list[(next() % list.len() as u64) as usize]
        }
        fn secret(serial: &mut u32, shape: &str) -> String {
            *serial += 1;
            match shape {
                "plain" => format!("Sq{serial}xk9"),
                "punct" => format!("S.q{serial}-x_9~"),
                "pct" => format!("Sq%20{serial}x"),
                "pw" => format!("P{serial}w%40rd"),
                "user" => format!("U{serial}name"),
                "frag" => format!("F{serial}opaque"),
                other => other.to_owned(),
            }
        }
        fn pairs(next: &mut impl FnMut() -> u64, serial: &mut u32, url: &mut String) {
            const VALUES: &[&str] = &[
                "plain",
                "plain",
                "punct",
                "pct",
                "[REDACTED_SECRET]",
                "redacted",
                "",
            ];
            for k in 0..1 + next() % 3 {
                if k > 0 {
                    url.push('&');
                }
                let key = pick(next, KEYS);
                let value = secret(serial, pick(next, VALUES));
                url.push_str(&format!("{key}={value}"));
            }
        }
        let mut url = pick(next, SCHEMES).to_owned();
        match pick(next, &["none", "user", "both", "pw"]) {
            "user" => url += &format!("{}@", secret(serial, "user")),
            "both" => url += &format!("{}:{}@", secret(serial, "user"), secret(serial, "pw")),
            "pw" => url += &format!(":{}@", secret(serial, "pw")),
            _ => {}
        }
        url += pick(next, HOSTS);
        url += pick(next, PATHS);
        if next().is_multiple_of(2) {
            url.push('?');
            pairs(next, serial, &mut url);
        }
        if next().is_multiple_of(2) {
            url.push('#');
            match pick(next, &["opaque", "pairs", "path"]) {
                "opaque" => url += &secret(serial, "frag"),
                "pairs" => pairs(next, serial, &mut url),
                _ => url += &format!("/route?q={}", secret(serial, "plain")),
            }
        }
        for _ in 0..next() % 4 {
            let at = (next() % (url.len() as u64 + 1)) as usize;
            url.insert(at, ['\t', '\n', '\r'][(next() % 3) as usize]);
        }
        url
    }

    /// Independent oracle over the [`generated_url`]s of an input: `url::Url::parse` reads each one (the parser drops
    /// TAB/LF/CR itself), and its username, password, every query or fragment value under a secret key and, for a URL
    /// that is not cannot-be-a-base, its whole fragment (and every piece of it) must be absent from the output with
    /// TAB/LF/CR removed. Pieces of fewer than three characters besides any marker, placeholders, pieces holding a placeholder (the scrub writes them, so a fragment can match a scrubbed query) and pieces that occur
    /// more than once in the input are not looked for. No sanitizer pattern or boundary is reused.
    fn generated_url_leak(urls: &[String], input: &str, output: &str) -> Option<String> {
        let strip = |s: &str| s.replace(['\t', '\n', '\r'], "");
        let (input, output) = (strip(input), strip(output));
        for raw in urls {
            let Ok(url) = url::Url::parse(raw) else {
                continue;
            };
            let mut secrets = Vec::new();
            for cred in [url.username(), url.password().unwrap_or("")] {
                secrets.push(cred.to_owned());
                secrets.push(percent_decode(cred));
            }
            for part in [url.query(), url.fragment()].into_iter().flatten() {
                for pair in part.split('&') {
                    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                    if ORACLE_SECRET_KEYS
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(&percent_decode(k)))
                    {
                        secrets.push(v.to_owned());
                        secrets.push(percent_decode(v));
                    }
                }
            }
            if let Some(fragment) = url.fragment().filter(|_| !url.cannot_be_a_base()) {
                secrets.push(fragment.to_owned());
                secrets.extend(fragment.split(['&', '=', '/', '?', '#']).map(str::to_owned));
            }
            for secret in secrets {
                if secret.replace(REDACTED, "").chars().count() >= 3
                    && !REDACTED.contains(&secret)
                    && !REDACTED_URL_VALUE.contains(&secret)
                    && !secret.contains(REDACTED_URL_VALUE)
                    && !secret.contains(REDACTED)
                    && input.matches(&secret).count() == 1
                    && output.contains(&secret)
                {
                    return Some(secret);
                }
            }
        }
        None
    }

    /// About 35 s unoptimised (each input is up to four generated URLs, scrubbed twice); the fuzz target runs the same
    /// generator from its bytes for depth.
    #[test]
    fn the_independent_url_oracle_finds_no_secret_in_50k_generated_inputs() {
        // Text between URLs: separators that end a URL, and junk that may glue to its neighbours inside one segment.
        const SEPARATORS: &[&str] = &[" ", "\u{a0}", "\n ", " \t", "\" ", "'", "<", "> ", " | "];
        const AROUND: &[&str] = &["", "", "(", "TOKEN=", "next=", "url:"];
        const AFTER: &[&str] = &["", "", ")", ".", ",", ").", ";"];
        const JUNK: &[&str] = &[
            "see",
            "mail alice@example.com",
            "TOKEN=[REDACTED_SECRET]",
            "DB_PASSWORD=",
            r"C:\Users\me\@types",
            "std::vec::Vec#push",
            "ab:",
            "https://",
            "x://",
            "@",
            "p@ss",
            "#",
            "?code=",
            "\n",
            "%40",
        ];
        let mut state = 0x6a09_e667_f3bc_c909_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut serial = 0;
        for _ in 0..20_000 {
            let mut input = String::new();
            let mut urls = Vec::new();
            for segment in 0..1 + next() % 4 {
                if segment > 0 {
                    input += SEPARATORS[(next() % SEPARATORS.len() as u64) as usize];
                }
                if next().is_multiple_of(3) {
                    input += JUNK[(next() % JUNK.len() as u64) as usize];
                    continue;
                }
                let url = generated_url(&mut next, &mut serial);
                input += AROUND[(next() % AROUND.len() as u64) as usize];
                input += &url;
                input += AFTER[(next() % AFTER.len() as u64) as usize];
                urls.push(url);
            }
            let out = redact_secrets(&input).into_owned();
            if let Some(secret) = generated_url_leak(&urls, &input, &out) {
                panic!("{secret:?} survived in {out:?} for {input:?}");
            }
            assert_eq!(redact_secrets(&out), out, "not a fixed point for {input:?}");
        }
    }

    /// Alphanumeric runs of six or more characters in `s`, percent-decoded and lower-cased (the 1.0.45 scrub
    /// re-serialised URLs: it decoded and re-encoded query text and lower-cased hosts and schemes).
    fn differential_words(s: &str) -> Vec<String> {
        percent_decode(s)
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| w.len() >= 6 && !"redacted_secret".contains(*w))
            .map(str::to_owned)
            .collect()
    }

    /// Every word (see [`differential_words`]) of `input` that the frozen 1.0.45 redactor removed and the current one
    /// keeps, for the telemetry flavour and the credential-shape flavour. The caller holds the credential registry
    /// lock with the registry empty, so both `redact_secrets` are their shape scrubs.
    fn regressions_vs_1045(input: &str) -> Vec<(String, &'static str, String, String)> {
        type Scrub = fn(&str) -> Cow<'_, str>;
        let flavours: [(&'static str, Scrub, Scrub); 2] = [
            (
                "telemetry",
                frozen_1045::redact_secrets,
                super::redact_secrets,
            ),
            (
                "credential-shapes",
                frozen_1045::redact_credential_shapes,
                super::redact_credential_shapes,
            ),
        ];
        let mut found = Vec::new();
        for (flavour, old, new) in flavours {
            let old = old(input).into_owned();
            let new = new(input).into_owned();
            let old_norm = percent_decode(&old).to_ascii_lowercase();
            let new_norm = percent_decode(&new).to_ascii_lowercase();
            for word in differential_words(input) {
                if !old_norm.contains(&word) && new_norm.contains(&word) {
                    found.push((word, flavour, old.clone(), new.clone()));
                }
            }
        }
        found
    }

    /// String literals (plain and raw) in Rust source, unescaped; enough of the syntax for this file's tests.
    fn string_literals(source: &str) -> Vec<String> {
        let b = source.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
                i += source[i..].find('\n').unwrap_or(source.len() - i);
                continue;
            }
            if b[i] == b'\'' {
                // A char literal such as '"' must not open a string; a lifetime has no closing quote nearby.
                if let Some(len) = source[i + 1..].find('\'').filter(|&l| l <= 10) {
                    i += len + 2;
                    continue;
                }
            }
            let raw_hashes = (b[i] == b'r' && (i == 0 || !b[i - 1].is_ascii_alphanumeric()))
                .then(|| source[i + 1..].bytes().take_while(|&c| c == b'#').count())
                .filter(|&h| b.get(i + 1 + h) == Some(&b'"'));
            if let Some(h) = raw_hashes {
                let body = i + 2 + h;
                let close = format!("\"{}", "#".repeat(h));
                let Some(len) = source[body..].find(&close) else {
                    break;
                };
                out.push(source[body..body + len].to_owned());
                i = body + len + close.len();
                continue;
            }
            if b[i] != b'"' {
                i += 1;
                continue;
            }
            let mut s = String::new();
            let mut chars = source[i + 1..].char_indices();
            let mut end = source.len();
            while let Some((at, ch)) = chars.next() {
                match ch {
                    '"' => {
                        end = i + 1 + at + 1;
                        break;
                    }
                    '\\' => match chars.next().map(|(_, e)| e) {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('0') => s.push('\0'),
                        Some('u') => {
                            let hex: String = chars
                                .by_ref()
                                .map(|(_, c)| c)
                                .skip(1)
                                .take_while(|&c| c != '}')
                                .collect();
                            if let Some(c) =
                                u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                            {
                                s.push(c);
                            }
                        }
                        Some('x') => {
                            let hex: String = chars.by_ref().take(2).map(|(_, c)| c).collect();
                            if let Ok(c) = u8::from_str_radix(&hex, 16) {
                                s.push(c as char);
                            }
                        }
                        Some('\n') => {
                            while chars.clone().next().is_some_and(|(_, c)| c.is_whitespace()) {
                                chars.next();
                            }
                        }
                        Some(other) => s.push(other),
                        None => {}
                    },
                    other => s.push(other),
                }
            }
            out.push(s);
            i = end;
        }
        out
    }

    /// Text the differential test builds: URLs whose query or fragment keys name a credential in any spelling the
    /// parser decodes, special schemes glued to the word before them, `KEY=secret` assignments, and the oracle's
    /// [`generated_url`]s, joined by separators. `serial` makes every secret unique.
    fn differential_input(next: &mut impl FnMut() -> u64, serial: &mut u32) -> String {
        const KEYS: &[&str] = &[
            "db_password",
            "db_pass%77ord",
            "DB%5FPASSWORD",
            "my%2Dapi%2Dkey",
            "x.api-key",
            "MyToken",
            "user+token",
            "aws_secret_access_key",
            "client-secret",
            "pa%73%53word",
            "id_token",
            "token",
            "code",
            "page",
            "q",
            "tok%65n",
        ];
        const SCHEMES: &[&str] = &[
            "https://",
            "http://",
            "prefixhttps:///",
            "xhttp://",
            "Myftp://",
            "git+https://",
            "postgres://",
            "wss://",
        ];
        const NAMES: &[&str] = &[
            "DB_PASSWORD",
            "api_key",
            "GITHUB_TOKEN",
            "\"password\"",
            "client-secret",
            "secret_key",
            "x.token",
        ];
        const SEPS: &[&str] = &["=", ": ", " = ", ":", "=\"", "='"];
        const JOIN: &[&str] = &[" ", "\n", "\t", ", ", " | ", "(", ") ", "\"", "&"];
        fn pick(next: &mut impl FnMut() -> u64, list: &[&'static str]) -> &'static str {
            list[(next() % list.len() as u64) as usize]
        }
        let secret = |serial: &mut u32| {
            *serial += 1;
            format!("Swordfish{serial}q")
        };
        let mut input = String::new();
        const AFFIXES: &[&str] = &[
            "...",
            "\u{2026}",
            "<...>",
            "xxx",
            "****",
            "changeme",
            "${VAR}",
            "$TOKEN",
            "<your-token>",
            "",
        ];
        for part in 0..1 + next() % 4 {
            if part > 0 {
                input += pick(next, JOIN);
            }
            let part_start = input.len();
            match next() % 6 {
                0 => {
                    input += pick(next, SCHEMES);
                    if next().is_multiple_of(2) {
                        input += &format!("alice:{}@", secret(serial));
                    }
                    // u46 spans5: the host or a path segment may itself be `name=secret`.
                    match next() % 4 {
                        0 => input += &format!("password={}/p", secret(serial)),
                        1 => {
                            input +=
                                &format!("host.example/{}={}", pick(next, KEYS), secret(serial))
                        }
                        _ => input += "host.example/p",
                    }
                    let lead = if next().is_multiple_of(3) { "#" } else { "?" };
                    input += lead;
                    for k in 0..1 + next() % 3 {
                        if k > 0 {
                            input.push('&');
                        }
                        input += &format!("{}={}", pick(next, KEYS), secret(serial));
                    }
                }
                1 => {
                    input += &format!(
                        "{}{}{}",
                        pick(next, NAMES),
                        pick(next, SEPS),
                        secret(serial)
                    );
                }
                2 => input += &generated_url(next, serial),
                // u46 spans4: `NAME=VALUE` where VALUE is a secret or a URL carrying one in its path, query or
                // fragment, with placeholder-like text before, after or inside it.
                3 | 4 => {
                    input += pick(next, NAMES);
                    input += pick(next, SEPS);
                    input += pick(next, AFFIXES);
                    if next().is_multiple_of(5) {
                        input += &secret(serial);
                    } else {
                        input += pick(next, SCHEMES);
                        input += "h.example/";
                        if next().is_multiple_of(2) {
                            input += &secret(serial);
                            input += pick(next, AFFIXES);
                        }
                        if next().is_multiple_of(2) {
                            input += &format!("?{}={}", pick(next, KEYS), secret(serial));
                            input += pick(next, AFFIXES);
                        }
                        if next().is_multiple_of(2) {
                            input += &format!("#{}", secret(serial));
                        }
                    }
                    input += pick(next, AFFIXES);
                }
                _ => {
                    input += pick(
                        next,
                        &["see the docs", "ok", "Makefile:3: git@host", "C:\\x\\@y"],
                    )
                }
            }
            // u46 spans5: percent-encode random characters of the part (userinfo, host, path, query, fragment, or a
            // plain assignment's name, separator and value), key letters and `= : @` included. A scheme is left
            // alone, one time in four: an escaped scheme is no URL, so nothing behind it gets decoded.
            if next().is_multiple_of(2) {
                let keep = match input[part_start..].find("://") {
                    Some(at) if !next().is_multiple_of(4) => part_start + at + 3,
                    _ => part_start,
                };
                let encoded = percent_encode_some(next, &input[keep..]);
                input.truncate(keep);
                input += &encoded;
            }
        }
        input
    }

    /// `s` with about one ASCII character in five (one in two for `= : @ /`, and for letters of a credential word)
    /// written as a `%XX` escape, upper- or lower-case hex at random.
    fn percent_encode_some(next: &mut impl FnMut() -> u64, s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 2);
        for ch in s.chars() {
            let rate = if "=:@/".contains(ch) || "PASWORDTKENYICLpaswordtkenyicl".contains(ch) {
                2
            } else {
                5
            };
            if ch.is_ascii() && next().is_multiple_of(rate) {
                let escape = format!("%{:02X}", ch as u32);
                if next().is_multiple_of(2) {
                    out += &escape.to_ascii_lowercase();
                } else {
                    out += &escape;
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// Nothing the released 1.0.45 redactor removed may survive the current one (u46 r8: two such regressions were
    /// found by review, not tests). The corpus: every string literal in this file and the integration test (each alone
    /// and joined to the next, as `fixture` joins its parts), every committed fuzz seed and regression input, and 12k
    /// [`differential_input`]s (under 30 s in a debug build; set `SANITIZER_DIFFERENTIAL_INPUTS` for a longer run).
    #[test]
    fn nothing_the_1045_redactor_removed_survives() {
        let mut corpus: Vec<String> = Vec::new();
        for source in [
            include_str!("sanitizer.rs"),
            include_str!("../tests/p119_credentials.rs"),
        ] {
            let literals = string_literals(source);
            corpus.extend(literals.windows(2).map(|w| format!("{}{}", w[0], w[1])));
            corpus.extend(literals);
        }
        let fuzz = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fuzz");
        let mut fuzz_inputs = 0;
        for dir in ["seeds/sanitizer", "regressions/sanitizer"] {
            let entries =
                std::fs::read_dir(fuzz.join(dir)).unwrap_or_else(|e| panic!("{dir}: {e}"));
            for entry in entries.flatten() {
                if let Ok(text) = std::fs::read(entry.path()).map(String::from_utf8) {
                    corpus.extend(text.ok());
                    fuzz_inputs += 1;
                }
            }
        }
        assert!(
            fuzz_inputs >= 10,
            "fuzz inputs not found under {}",
            fuzz.display()
        );
        let mut state = 0xbb67_ae85_84ca_a73b_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut serial = 0;
        // `SANITIZER_DIFFERENTIAL_INPUTS` raises the count for a manual run (u46 spans5: one 100k run per change).
        let generated = std::env::var("SANITIZER_DIFFERENTIAL_INPUTS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(12_000);
        for _ in 0..generated {
            corpus.push(differential_input(&mut next, &mut serial));
        }
        let _registry = crate::sent_credentials::REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::sent_credentials::clear_for_tests();
        let mut failures = Vec::new();
        for input in &corpus {
            for (word, flavour, old, new) in regressions_vs_1045(input) {
                failures.push(format!(
                    "{flavour}: {word:?} removed by 1.0.45 survives\n  input: {input:?}\n  1.0.45: {old:?}\n  now:    {new:?}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} regression(s) vs 1.0.45 over {} inputs; first ones:\n{}",
            failures.len(),
            corpus.len(),
            failures
                .iter()
                .take(12)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// u46 spans5: an assignment spelled with percent escapes in any URL component (or outside a URL) is redacted.
    /// 1.0.45 decoded hosts and query keys before the assignment rule ran, so `https://%70assword=swordfish987/` lost
    /// its value; the rule now reads a decoded view of the whole text and redacts at the original bytes.
    #[test]
    fn spans5_percent_encoded_assignments_are_redacted() {
        let clean = |s: &str| redact_secrets(s).into_owned();
        for (input, secret) in [
            ("https://%70assword=swordfish987/", "swordfish987"),
            ("https://%50ASSWORD=Swordfish987/", "Swordfish987"),
            ("https://%50aSsWoRd=Swordfish987/x", "Swordfish987"),
            ("https://password%3Dswordfish987/", "swordfish987"),
            ("https://password%3dswordfish987/", "swordfish987"),
            ("https://h/%70assword=Swordfish987", "Swordfish987"),
            ("https://h/a/pass%77ord%3DSwordfish987/b", "Swordfish987"),
            ("https://h/x?q=%74oken%3DSwordfish987", "Swordfish987"),
            ("https://h/x#api%5Fkey%3ASwordfish987", "Swordfish987"),
            ("https://u%3Apass@h/%70assword=Swordfish987", "Swordfish987"),
            ("myapp://h/%73ecret=Swordfish987", "Swordfish987"),
            ("DB_%50ASSWORD=Swordfish987", "Swordfish987"),
            ("password%3D%53wordfish987", "wordfish987"),
            (
                "see https://%70assword=swordfish987 and more",
                "swordfish987",
            ),
            // Found by the differential test: a valueless last query pair under a credential key takes the next word.
            (
                "https://h/p?a=1&db_password\n\nSwordfish987",
                "Swordfish987",
            ),
            ("https://h/p?a=1&db_pass%77ord Swordfish987", "Swordfish987"),
            ("https://h/p?db_password=\"Swordfish987\"", "Swordfish987"),
            (
                "https://h/p?a=1&x%3D1%24TOKEN\n\nSwordfish987",
                "Swordfish987",
            ),
            // Found by the differential test: an escaped `&` does not end the value.
            (
                "https://%70assword%3DSwordfish987/p?x%3D1%26code=Swordfish988&a=b",
                "Swordfish988",
            ),
            // Found by the differential test: an ellipsis spelled with escapes is no placeholder.
            (
                "https://h/?cli%65nt-secret=\"Swordfish987%2e%2e.",
                "Swordfish987",
            ),
        ] {
            let out = clean(input);
            assert!(
                !out.contains(secret) && out.contains(REDACTED),
                "{input:?} -> {out:?}"
            );
            assert_eq!(clean(&out), out, "not a fixed point for {input:?}");
        }
        // Escapes alone, and an escaped assignment of a placeholder, stay.
        for input in [
            "https://h/a%20b?q=x%2Fy",
            "https://h/%24%7BTOKEN%7D",
            "100%25 done",
        ] {
            assert_eq!(clean(input), input);
        }
    }

    /// u46 spans4: an assignment whose value 1.0.45 redacted is redacted. The URL pass of 1.0.45 dropped a fragment
    /// before the assignment rule saw the value, so a trailing `...` inside the fragment did not make it a placeholder.
    #[test]
    fn spans4_ellipsis_in_a_url_fragment_is_not_a_placeholder() {
        let clean = |s: &str| redact_secrets(s).into_owned();
        for (input, secret) in [
            ("api_key=https://h/Swordfish987#view...", "Swordfish987"),
            ("token=https://h/Swordfish987#a...", "Swordfish987"),
            ("token=https://h/Swordfish987#a\u{2026}", "Swordfish987"),
            ("secret_key=https://h/Swordfish987?x=1#a...", "Swordfish987"),
            (
                "token=https://h/Swordfish987?code=Swordfish988...&ok",
                "Swordfish988",
            ),
            (
                "token=https://h/Swordfish987...?code=Swordfish988&x...",
                "Swordfish987",
            ),
            ("token=https://h/Swordfish987\u{2026}", "Swordfish987"),
            (
                "token=prefixhttps:///h/Swordfish987\u{2026}",
                "Swordfish987",
            ),
            (
                "x=1 https://h/?db_pass%77ord=Swordfish987<a>#Swordfish988...",
                "Swordfish988",
            ),
            ("password=foo...bar", "foo"),
            ("password=Swordfish987...", "Swordfish987"),
        ] {
            let out = clean(input);
            assert!(!out.contains(secret), "{input:?} leaked: {out:?}");
            assert_eq!(clean(&out), out, "not a fixed point for {input:?}");
        }
        assert_eq!(
            clean("api_key=https://h/Swordfish987#view..."),
            "api_key=[REDACTED_SECRET]"
        );
        // Still placeholders: an ellipsis with no URL fragment.
        for input in [
            "token=eyJhbGciOi...",
            "api_key=abcd...",
            "token=https://h/x?a=b...",
        ] {
            assert!(
                matches!(redact_secrets(input), Cow::Borrowed(_)),
                "{input:?} -> {:?}",
                redact_secrets(input)
            );
        }
    }

    /// u46 r8: a query or fragment key the assignment rule reads as a credential name loses its value however the
    /// parser spells it (percent escapes in any case, `+`), as through 1.0.45; a special scheme glued to the word
    /// before it still has its userinfo removed when two slashes follow, but not without them.
    #[test]
    fn r8_decoded_credential_keys_and_glued_special_schemes() {
        let clean = |s: &str| redact_secrets(s).into_owned();
        for (input, secret) in [
            ("https://h/?db_pass%77ord=Swordfish987", "Swordfish987"),
            ("https://h/?DB%5fPASSWORD=Swordfish987&x=1", "Swordfish987"),
            ("https://h/?my+api%2Dkey=Swordfish987", "Swordfish987"),
            ("https://h/p?x.Api-Key=Swordfish987", "Swordfish987"),
            ("https://h/?MyToken=Swordfish987", "Swordfish987"),
            (
                "myapp://h/?session%5Fsecret=Swordfish987 tail",
                "Swordfish987",
            ),
            ("prefixhttps:///alice:Swordfish987@host/", "Swordfish987"),
            ("prefixhttps:///alice:Swordfish987@host/", "alice"),
            ("xHTTP://alice:Swordfish987@host/", "Swordfish987"),
            ("seeftp:\\\\alice:Swordfish987@host/", "Swordfish987"),
        ] {
            let out = clean(input);
            assert!(
                !out.contains(secret),
                "{secret:?} survived in {out:?} for {input:?}"
            );
            assert_eq!(clean(&out), out, "not a fixed point for {input:?}");
        }
        assert_eq!(
            clean("https://h/?db_pass%77ord=Swordfish987"),
            "https://h/?db_pass%77ord=[REDACTED_SECRET]"
        );
        assert_eq!(
            clean("prefixhttps:///alice:Swordfish987@host/"),
            "prefixhttps:///host/"
        );
        // spans3 differential finding: a value that runs into the next assignment's name no longer hides it.
        for (input, secret) in [
            (
                "https://h/p#token=Swordfish9277q(secret_key='Swordfish9278q) x",
                "Swordfish9278q",
            ),
            (
                "id_token=Swordfish16655q(client-secret: Swordfish16656q",
                "Swordfish16656q",
            ),
            ("token=Swordfish1(DB_PASSWORD=\"Swordfish2\"", "Swordfish2"),
            (
                "x.token=abcdefgh(\"password\": \"Swordfish3\"",
                "Swordfish3",
            ),
        ] {
            let out = clean(input);
            assert!(
                !out.contains(secret),
                "{secret:?} survived in {out:?} for {input:?}"
            );
            assert_eq!(clean(&out), out, "not a fixed point for {input:?}");
        }
        for kept in [
            "Makefile:3: error from git@host.example",
            "profile:alice@example.com",
            "https://h/?page=2&passwordless=1",
            "https://h/?tokens=12345678",
        ] {
            assert_eq!(clean(kept), kept);
        }
    }

    /// u46 spans6: a query value that started at the `?` ending an authority (`s:?t://token=?`) was written as the
    /// marker, the next pass read a userinfo where that `?` had been and removed it, one hop per two passes, so a
    /// chain was left half-done at the pass cap. The fuzz crash inputs (committed under `fuzz/regressions/sanitizer`)
    /// and longer chains now reach their fixed point in one call, and no redaction takes an authority's terminator.
    #[test]
    fn spans6_redaction_keeps_the_authority_terminator() {
        let clean = |s: &str| redact_secrets(s).into_owned();
        // Repeated calls until nothing changes (bounded): the one-call result must already be that fixed point.
        let settled = |s: &str| {
            let mut out = clean(s);
            for _ in 0..64 {
                let next = clean(&out);
                if next == out {
                    break;
                }
                out = next;
            }
            out
        };
        let fuzz = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fuzz/regressions/sanitizer");
        let mut inputs: Vec<String> = [
            "crash-59925ef53a4fe11d25c79b9aa908400a97bc4494",
            "crash-assignment-userinfo-chain",
            "crash-marker-took-authority-end",
            "crash-query-value-chain-long",
        ]
        .iter()
        .map(|name| {
            let bytes = std::fs::read(fuzz.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .collect();
        for hops in [1, 2, 3, 8, 40] {
            inputs.push(format!(
                "s:?t://token=?{}'@token=abcdef",
                "'@token=?".repeat(hops)
            ));
            inputs.push(format!(
                "s:?t://token=?Swordfish1{}'@token=abcdef",
                "'@token=?Swordfish1".repeat(hops)
            ));
            inputs.push(format!(
                "s:?t://token=/{}'@token=abcdef",
                "'@token=/".repeat(hops)
            ));
        }
        for input in &inputs {
            let once = clean(input);
            assert_eq!(
                once,
                settled(input),
                "one call is not the fixed point for {input:?}"
            );
            assert_eq!(clean(&once), once, "not idempotent for {input:?}");
        }
        // A lone `?` (or `/`) value is the authority's end, not a secret: kept, and the text is a fixed point.
        for kept in ["s:?t://token=?", "s:?t://token=/", "s:?t://token=?'@h"] {
            assert_eq!(clean(kept), kept);
        }
        // What follows the terminator is still redacted, the terminator stays.
        for (input, want) in [
            ("s:?t://token=?abc", "s:?t://token=?[REDACTED_SECRET]"),
            (
                "s:?t://token=?Swordfish1'@h",
                "s:?t://token=?[REDACTED_SECRET]'@h",
            ),
        ] {
            assert_eq!(clean(input), want);
        }
        // Ordinary URLs are unchanged by the rule: their values sit past the authority.
        assert_eq!(
            clean("https://h/p?token=abc/def?x#frag"),
            "https://h/p?token=[REDACTED_SECRET]"
        );
    }

    /// u46 spans7: a query value under a marker key ended at a backtick (a URL ends there), but the assignment rule
    /// reads a backtick as part of a value, so the next pass took it from `token=[REDACTED_SECRET]` + backtick and
    /// joined the run to the text after it; each hop took two passes and a chain was left half-done at the pass cap
    /// (fuzz crash, committed as `fuzz/regressions/sanitizer/crash-marker-value-backtick`). The value now runs on
    /// past the backtick, as the assignment rule reads it, and one call reaches the fixed point.
    #[test]
    fn spans7_marker_value_runs_past_a_backtick() {
        let clean = |s: &str| redact_secrets(s).into_owned();
        let fuzz = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../fuzz/regressions/sanitizer/crash-marker-value-backtick");
        let crash =
            String::from_utf8_lossy(&std::fs::read(&fuzz).expect("crash input")).into_owned();
        let once = clean(&crash);
        assert_eq!(clean(&once), once, "not idempotent for {crash:?}");
        for hops in [1, 2, 3, 8, 40] {
            let input = format!("https://h/p?token=bc`{}&x=2", "&p?token=bc`".repeat(hops));
            let want = format!(
                "https://h/p?token=[REDACTED_SECRET]{}&x=2",
                "&p?token=[REDACTED_SECRET]".repeat(hops)
            );
            assert_eq!(clean(&input), want, "for {input:?}");
            assert_eq!(clean(&want), want);
        }
        // A backtick still ends a URL before a value opens.
        assert_eq!(clean("`https://h/p`?token=abc"), "`https://h/p`?token=abc");
    }
}
