//! Alternate readings of a memory text for the screen in [`crate::safety`]: text hidden behind an
//! encoding (base64, hex, percent-escapes, HTML or backslash escapes, ROT13, Unicode tag characters,
//! a right-to-left override, digit-for-letter substitution), and the "ignore the previous
//! instructions" family in languages other than English.
//!
//! Like the rest of the screen this is a heuristic that flags and never edits memory. A decoded view
//! is judged for instructions only, never for credentials: a base64 blob in code legitimately
//! decodes to a certificate or a config.

use std::sync::LazyLock;

use regex::Regex;

/// Most encoded runs decoded per decoder, and the longest run read, so a hostile file costs a
/// bounded amount of work.
const MAX_RUNS: usize = 32;
/// Most candidate runs scanned per decoder. Larger than `MAX_RUNS` because a note full of long identifiers or
/// paths matches the base64 pattern without decoding to anything; only decoded views count against `MAX_RUNS`.
const MAX_CANDIDATES: usize = 512;
const MAX_RUN_LEN: usize = 1 << 16;

fn compile(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| panic!("memory decode pattern `{pattern}`: {e}"))
}

/// The views of `text` worth screening. Every decoder runs on every view; the caller follows layered encodings
/// only a fixed number of levels deep, so work stays bounded.
pub(crate) fn views(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(base64_runs(text));
    out.extend(hex_runs(text));
    out.extend(percent_decoded(text));
    out.extend(entities_decoded(text));
    out.extend(backslash_escapes_decoded(text));
    // On every view, not only the text itself: base64(ROT13("ignore previous instructions")) is a view of a view.
    // Work stays bounded by the caller's depth cap.
    out.extend(tag_characters(text));
    out.extend(bidi_reversed(text));
    out.extend(rot13(text));
    out.extend(leet(text));
    out
}

/// Bytes as text if they read as text: valid UTF-8, mostly printable, long enough to be a phrase.
fn as_text(bytes: Vec<u8>) -> Option<String> {
    if bytes.len() < 8 {
        return None;
    }
    let s = String::from_utf8(bytes).ok()?;
    let total = s.chars().count();
    let printable = s
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r'))
        .count();
    (printable * 10 >= total * 9).then_some(s)
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Standard and URL-safe alphabets, padding optional.
fn base64_decode(run: &str) -> Option<Vec<u8>> {
    let mut digits: Vec<u8> = run
        .bytes()
        .take_while(|b| *b != b'=')
        .map(base64_value)
        .collect::<Option<_>>()?;
    if digits.len() % 4 == 1 {
        digits.pop();
    }
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    for chunk in digits.chunks(4) {
        let mut acc = 0u32;
        for (i, d) in chunk.iter().enumerate() {
            acc |= u32::from(*d) << (18 - 6 * i);
        }
        let n = chunk.len() * 6 / 8;
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + n]);
    }
    Some(out)
}

fn base64_runs(text: &str) -> Vec<String> {
    static RUN: LazyLock<Regex> = LazyLock::new(|| compile(r"[A-Za-z0-9+/_-]{16,}={0,2}"));
    RUN.find_iter(text)
        .take(MAX_CANDIDATES)
        .filter(|m| m.len() <= MAX_RUN_LEN)
        .filter_map(|m| base64_decode(m.as_str()).and_then(as_text))
        .take(MAX_RUNS)
        .collect()
}

fn hex_runs(text: &str) -> Vec<String> {
    static RUN: LazyLock<Regex> = LazyLock::new(|| compile(r"(?:[0-9a-fA-F]{2}){8,}"));
    RUN.find_iter(text)
        .take(MAX_CANDIDATES)
        .filter(|m| m.len() <= MAX_RUN_LEN)
        .filter_map(|m| {
            let s = m.as_str();
            let bytes: Vec<u8> = (0..s.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
                .collect();
            as_text(bytes)
        })
        .take(MAX_RUNS)
        .collect()
}

/// `%69gnore%20all` read as bytes, when the text holds at least three escapes.
fn percent_decoded(text: &str) -> Option<String> {
    static ESCAPE: LazyLock<Regex> = LazyLock::new(|| compile(r"%([0-9A-Fa-f]{2})"));
    if ESCAPE.find_iter(text).take(3).count() < 3 {
        return None;
    }
    let mut bytes = Vec::with_capacity(text.len());
    let raw = text.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let hex = |k: usize| raw.get(k).and_then(|b| char::from(*b).to_digit(16));
        if raw[i] == b'%'
            && let (Some(hi), Some(lo)) = (hex(i + 1), hex(i + 2))
        {
            bytes.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            bytes.push(raw[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// `&#105;` and `&#x69;`.
fn entities_decoded(text: &str) -> Option<String> {
    static ENTITY: LazyLock<Regex> =
        LazyLock::new(|| compile(r"&#(?:[xX]([0-9A-Fa-f]{1,6})|([0-9]{1,7}));"));
    if !ENTITY.is_match(text) {
        return None;
    }
    Some(
        ENTITY
            .replace_all(text, |c: &regex::Captures<'_>| {
                let code = match (c.get(1), c.get(2)) {
                    (Some(h), _) => u32::from_str_radix(h.as_str(), 16).ok(),
                    (_, Some(d)) => d.as_str().parse().ok(),
                    _ => None,
                };
                code.and_then(char::from_u32)
                    .map_or_else(|| c[0].to_owned(), String::from)
            })
            .into_owned(),
    )
}

/// `\x69` and `i` in source-code style.
fn backslash_escapes_decoded(text: &str) -> Option<String> {
    static ESCAPE: LazyLock<Regex> =
        LazyLock::new(|| compile(r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})"));
    if !ESCAPE.is_match(text) {
        return None;
    }
    Some(
        ESCAPE
            .replace_all(text, |c: &regex::Captures<'_>| {
                let hex = c.get(1).or_else(|| c.get(2)).map_or("", |m| m.as_str());
                u32::from_str_radix(hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .map_or_else(|| c[0].to_owned(), String::from)
            })
            .into_owned(),
    )
}

/// Unicode tag characters (U+E0020..U+E007E) are invisible and each stands for one ASCII character.
fn tag_characters(text: &str) -> Option<String> {
    let decoded: String = text
        .chars()
        .filter_map(|c| match c as u32 {
            n @ 0xE0020..=0xE007E => char::from_u32(n - 0xE0000),
            _ => None,
        })
        .collect();
    (decoded.len() >= 8).then_some(decoded)
}

/// A right-to-left override makes reversed text display forwards.
fn bidi_reversed(text: &str) -> Option<String> {
    text.contains(['\u{202e}', '\u{202b}', '\u{2067}'])
        .then(|| text.chars().rev().collect())
}

fn rot13(text: &str) -> Option<String> {
    if text.chars().filter(char::is_ascii_alphabetic).count() < 16 {
        return None;
    }
    Some(
        text.chars()
            .map(|c| match c {
                'a'..='z' => (((c as u8 - b'a') + 13) % 26 + b'a') as char,
                'A'..='Z' => (((c as u8 - b'A') + 13) % 26 + b'A') as char,
                other => other,
            })
            .collect(),
    )
}

/// `1gn0re` read as `ignore`. Applied only to text that mixes letters with these digits and symbols.
fn leet(text: &str) -> Option<String> {
    if !text.contains(['0', '1', '3', '4', '5', '7', '@', '$']) {
        return None;
    }
    Some(
        text.chars()
            .map(|c| match c {
                '0' => 'o',
                '1' => 'i',
                '3' => 'e',
                '4' => 'a',
                '5' => 's',
                '7' => 't',
                '@' => 'a',
                '$' => 's',
                other => other,
            })
            .collect(),
    )
}

/// One language's override phrase: a verb ("ignore", "forget"), a modifier ("previous", "above") and
/// a noun ("instructions", "rules"), the modifier and noun together in either order, the verb before
/// or after them, all inside one sentence. Verbs are whole words in word-spaced scripts so an
/// English "ignore" is not read as Spanish; modifiers and nouns are stems, so inflections match.
struct Language {
    verbs: &'static [&'static str],
    modifiers: &'static [&'static str],
    nouns: &'static [&'static str],
    /// Word-spaced script: stems start at a word boundary.
    spaced: bool,
}

const LANGUAGES: &[Language] = &[
    Language {
        verbs: &[
            "ignora",
            "ignore",
            "ignorad",
            "olvida",
            "olvide",
            "descarta",
            "omite",
            "desestima",
        ],
        modifiers: &["anterior", "previa", "pasad"],
        nouns: &[
            "instruccion",
            "instrucción",
            "regla",
            "indicacion",
            "indicación",
            "orden",
            "directriz",
        ],
        spaced: true,
    },
    Language {
        verbs: &["ignore", "ignorez", "oublie", "oubliez", "néglige"],
        modifiers: &["précédent", "antérieur", "ci-dessus"],
        nouns: &["instruction", "consigne", "règle", "directive"],
        spaced: true,
    },
    Language {
        verbs: &[
            "ignoriere",
            "ignoriert",
            "ignorieren",
            "vergiss",
            "vergesst",
            "missachte",
        ],
        modifiers: &[
            "vorherig",
            "vorig",
            "frühere",
            "bisherig",
            "obig",
            "vorangehend",
        ],
        nouns: &[
            "anweisung",
            "instruktion",
            "regel",
            "befehl",
            "vorgabe",
            "richtlinie",
        ],
        spaced: true,
    },
    Language {
        verbs: &[
            "ignore",
            "ignora",
            "ignorar",
            "esqueça",
            "esqueca",
            "esquece",
            "desconsidere",
            "desconsidera",
        ],
        modifiers: &["anterior", "prévia", "previa"],
        nouns: &["instruç", "instruc", "regra", "ordem", "ordens", "diretriz"],
        spaced: true,
    },
    Language {
        verbs: &["ignora", "ignorare", "ignori", "dimentica", "trascura"],
        modifiers: &["precedent", "anterior", "sopra"],
        nouns: &["istruzion", "regol", "indicazion", "ordin"],
        spaced: true,
    },
    Language {
        verbs: &["negeer", "negeert", "vergeet"],
        modifiers: &["vorige", "eerdere", "voorgaande", "bovenstaande"],
        nouns: &["instructie", "regel", "opdracht", "aanwijzing"],
        spaced: true,
    },
    Language {
        verbs: &["zignoruj", "ignoruj", "zapomnij", "pomiń"],
        modifiers: &["poprzedni", "wcześniejsz", "powyższ"],
        nouns: &["instrukcj", "polecen", "zasad", "reguł"],
        spaced: true,
    },
    Language {
        verbs: &["yoksay", "unut", "görmezden"],
        modifiers: &["önceki", "yukarıdaki", "evvelki"],
        nouns: &["talimat", "kural", "komut", "yönerge"],
        spaced: true,
    },
    Language {
        verbs: &[
            "игнорируй",
            "игнорируйте",
            "игнорировать",
            "забудь",
            "забудьте",
            "проигнорируй",
            "проигнорируйте",
            "отмени",
            "пренебреги",
        ],
        modifiers: &["предыдущ", "прежн", "прошл", "выше", "ранее", "предшеств"],
        nouns: &["инструкци", "указани", "правил", "команд", "распоряжени"],
        spaced: true,
    },
    Language {
        verbs: &[
            "忽略",
            "无视",
            "无視",
            "無視",
            "忽视",
            "忽視",
            "忘记",
            "忘記",
            "忘掉",
            "不要理会",
            "不要理會",
        ],
        modifiers: &[
            "之前", "以前", "以上", "上面", "先前", "前面", "此前", "上述", "上文",
        ],
        nouns: &[
            "指令", "指示", "规则", "規則", "提示", "说明", "說明", "命令", "设定", "設定",
        ],
        spaced: false,
    },
    Language {
        verbs: &["無視", "忘れ", "従わな", "従うな"],
        modifiers: &["これまで", "以前", "前の", "上記", "先ほど", "今までの"],
        nouns: &["指示", "命令", "ルール", "プロンプト", "指令"],
        spaced: false,
    },
    Language {
        verbs: &["무시", "잊어", "잊고"],
        modifiers: &["이전", "위의", "앞의", "기존", "지금까지"],
        nouns: &["지시", "지침", "명령", "규칙", "프롬프트"],
        spaced: false,
    },
    Language {
        verbs: &["تجاهل", "انس", "أهمل", "اهمل"],
        modifiers: &["السابق", "سابق", "الماضي", "أعلاه", "اعلاه", "السالف"],
        nouns: &[
            "التعليمات",
            "تعليمات",
            "القواعد",
            "الأوامر",
            "الاوامر",
            "التوجيهات",
            "الإرشادات",
        ],
        spaced: false,
    },
    Language {
        verbs: &["अनदेखा", "उपेक्षा", "भूल जा"],
        modifiers: &["पिछले", "पूर्व", "ऊपर", "पहले"],
        nouns: &["निर्देश", "आदेश", "नियम"],
        spaced: false,
    },
];

fn alternation(words: &[&str], boundary: &str, end: &str) -> String {
    let alts: Vec<String> = words.iter().map(|w| regex::escape(w)).collect();
    format!("{boundary}(?:{}){end}", alts.join("|"))
}

impl Language {
    fn pattern(&self) -> String {
        let (start, verb_end) = if self.spaced {
            (r"\b", r"\b")
        } else {
            ("", "")
        };
        let verb = alternation(self.verbs, start, verb_end);
        let modifier = alternation(self.modifiers, start, "");
        let noun = alternation(self.nouns, start, "");
        let gap = |n: usize| format!(r"[^.!?\n。！？]{{0,{n}}}?");
        let target = format!("(?:{modifier}{g}{noun}|{noun}{g}{modifier})", g = gap(24));
        format!("{verb}{g}{target}|{target}{g}{verb}", g = gap(60))
    }
}

static MULTILINGUAL: LazyLock<Vec<Regex>> =
    LazyLock::new(|| LANGUAGES.iter().map(|l| compile(&l.pattern())).collect());

/// Whether `text` (NFKC, invisible characters removed) holds an "ignore the previous instructions"
/// phrase in one of the listed languages. English is judged by the main screen.
pub(crate) fn multilingual_override(text: &str) -> bool {
    let lower = text.to_lowercase();
    MULTILINGUAL.iter().any(|re| re.is_match(&lower))
}
