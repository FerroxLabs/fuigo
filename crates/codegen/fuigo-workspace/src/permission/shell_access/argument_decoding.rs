use super::*;

#[derive(Clone, Copy)]
pub(crate) enum ShellFileMode {
    Read,
    Write,
    /// Empty dir/file creation (`mkdir`/`touch`): `Edit` for the inline-shell gate, not a content write.
    Create,
}

/// Tools that read/write a file named as an argument.
/// Not exhaustive; redirects are the robust catch-all (caught via the AST for any program).
pub(super) fn shell_file_mode(program: &str) -> Option<ShellFileMode> {
    match program {
        "cat" | "tac" | "nl" | "head" | "tail" | "grep" | "egrep" | "fgrep" | "rg" | "sed"
        | "awk" | "less" | "more" | "bat" | "strings" | "xxd" | "od" | "hexdump" | "base64"
        | "base32" | "cut" | "sort" | "uniq" | "wc" | "type" | "get-content" | "gc" | "diff"
        | "comm" | "rev" | "jq" | "yq" | "select-string" | "sls" | "ag" | "ack" | "zcat"
        | "zless" | "zmore" | "zgrep" | "zegrep" | "zfgrep" | "bzcat" | "bzgrep" | "xzcat"
        | "xzgrep" | "zstdcat" | "lz4cat" => Some(ShellFileMode::Read),
        "tee" | "set-content" | "out-file" | "add-content" | "tee-object" | "truncate" => {
            Some(ShellFileMode::Write)
        }
        _ => None,
    }
}

pub(super) fn shell_program_name(word: &str) -> &str {
    word.rsplit(['/', '\\']).next().unwrap_or(word)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExecutionScope {
    pub(super) start: usize,
    pub(super) end: usize,
}

impl ExecutionScope {
    pub(super) fn contains(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}

pub(super) struct ShellRedirectTarget {
    pub(super) path: Option<String>,
    /// Raw source text of the destination word (P166 r12: an undecodable one is scanned for protected names).
    pub(super) raw: String,
    pub(super) mode: ShellFileMode,
    pub(super) ambiguous: bool,
    pub(super) start_byte: usize,
    /// Where the redirect takes effect: bash opens a statement's redirects before running its body, so a redirect
    /// on `{ cd /etc; } > log` or `if cd /etc; then :; fi > log` writes in the cwd at the statement's start.
    pub(super) opens_at: usize,
    pub(super) scope: ExecutionScope,
}

pub(super) fn execution_scope(node: Node<'_>) -> ExecutionScope {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if current
            .next_sibling()
            .is_some_and(|sibling| sibling.kind() == "&")
        {
            let component = if current.kind() == "list" {
                current
            } else {
                parent
            };
            return ExecutionScope {
                start: component.start_byte(),
                end: component.end_byte(),
            };
        }
        if matches!(
            parent.kind(),
            "subshell" | "command_substitution" | "process_substitution"
        ) {
            return ExecutionScope {
                start: parent.start_byte(),
                end: parent.end_byte(),
            };
        }
        if parent.kind() == "pipeline" {
            return ExecutionScope {
                start: current.start_byte(),
                end: current.end_byte(),
            };
        }
        current = parent;
    }
    ExecutionScope {
        start: 0,
        end: usize::MAX,
    }
}

pub(super) struct CwdPoison {
    pub(super) at: usize,
    pub(super) scope: ExecutionScope,
}

/// In-scope `cd`/`pushd`/`popd` positions; relative later operands must Ask.
pub(super) fn cwd_poison_positions(root: Node<'_>, src: &str) -> Vec<CwdPoison> {
    let mut positions = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command"
            && node
                .child_by_field_name("name")
                .and_then(|name| name.utf8_text(src.as_bytes()).ok())
                .is_some_and(|program| {
                    matches!(shell_program_name(program), "cd" | "pushd" | "popd")
                })
        {
            positions.push(CwdPoison {
                at: node.start_byte(),
                scope: execution_scope(node),
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    positions
}

/// Whether an operand runs after a cwd change in its nearest execution scope.
pub(super) fn cwd_unpinned_before(
    positions: &[CwdPoison],
    at: usize,
    scope: ExecutionScope,
) -> bool {
    positions
        .iter()
        .any(|poison| poison.at < at && (poison.scope == scope || poison.scope.contains(scope)))
}

/// A command operand or redirect destination extracted from the AST, with escape/quote folding already applied to literals.
#[derive(Clone)]
pub(super) enum InvocationWord {
    Literal(String),
    Untrusted,
}

#[derive(Clone)]
pub(super) struct ShellInvocation {
    pub(super) start_byte: usize,
    pub(super) scope: ExecutionScope,
    pub(super) words: Vec<InvocationWord>,
    pub(super) wrapper_words: Vec<String>,
    /// What the parser saw but did not decode (P166 r8 tripwire input).
    pub(super) extras: CommandExtras,
    /// Glob facts from the shared normaliser, keyed by the word's text (quotes removed).
    pub(super) globs: InvocationGlobs,
}

/// Which words of one invocation are unquoted globs (patterns pathname expansion rewrites) and which carry glob
/// characters only quoted (literal names). Keyed by text: a text spelled both ways counts as a pattern.
#[derive(Clone, Default)]
pub(super) struct InvocationGlobs {
    pub(super) patterns: std::collections::HashSet<String>,
    pub(super) quoted: std::collections::HashSet<String>,
}

/// How the file gate must read one operand.
pub(super) enum OperandGlob {
    /// A literal path.
    Literal,
    /// An unquoted glob: checked as a pattern against the restricting rules.
    Pattern,
    /// Glob characters the normaliser did not decide (an undecoded word): fail closed as before.
    Ambiguous,
}

impl InvocationGlobs {
    pub(super) fn operand(&self, token: &str) -> OperandGlob {
        if self.patterns.contains(token) {
            OperandGlob::Pattern
        } else if shell_arg_is_ambiguous(token) && !self.quoted.contains(token) {
            OperandGlob::Ambiguous
        } else {
            OperandGlob::Literal
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct InvocationSlice<'a> {
    pub(super) words: &'a [InvocationWord],
}

pub(super) struct CheckedInvocationPeel<'a> {
    pub(super) words: InvocationSlice<'a>,
    pub(super) has_chdir: bool,
    pub(super) has_split_string: bool,
    pub(super) env_options_uncertain: bool,
    pub(super) exhausted: bool,
    pub(super) transparent_ambiguous: bool,
}

impl InvocationSlice<'_> {
    pub(super) fn literal_words(&self) -> Vec<String> {
        self.words
            .iter()
            .filter_map(|word| match word {
                InvocationWord::Literal(word) => Some(word.clone()),
                InvocationWord::Untrusted => None,
            })
            .collect()
    }

    pub(super) fn shell_words(&self) -> Vec<ShellWord<'_>> {
        self.words
            .iter()
            .map(|word| match word {
                InvocationWord::Literal(word) => ShellWord::Literal(word),
                InvocationWord::Untrusted => ShellWord::Untrusted,
            })
            .collect()
    }
}

pub(super) fn unwrap_invocation_checked(invocation: &ShellInvocation) -> CheckedInvocationPeel<'_> {
    // Parallel String/`InvocationWord` slices stay index-aligned under normalize.
    let norm = normalize_command_words(&invocation.wrapper_words);
    let peeled_count = invocation.wrapper_words.len() - norm.words.len();
    CheckedInvocationPeel {
        words: InvocationSlice {
            words: invocation.words.get(peeled_count..).unwrap_or_default(),
        },
        has_chdir: norm.has_chdir,
        has_split_string: norm.has_split_string,
        env_options_uncertain: norm.env_options_uncertain,
        exhausted: norm.exhausted,
        transparent_ambiguous: norm.ambiguous,
    }
}

pub(crate) enum ArgText {
    /// Literal path/word, no runtime expansion.
    Literal(String),
    /// Runtime expansion; unpinnable, so callers prompt.
    Ambiguous,
}

/// True if any descendant expands at runtime (e.g. `$X` in `.e"$X"`), so the text isn't a literal path.
pub(super) fn node_has_expansion(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        for i in 0..n.child_count() {
            let Some(child) = n.child(i) else { continue };
            if matches!(
                child.kind(),
                "expansion"
                    | "simple_expansion"
                    | "command_substitution"
                    | "arithmetic_expansion"
                    | "process_substitution"
            ) {
                return true;
            }
            stack.push(child);
        }
    }
    false
}

/// Drive-letter / UNC-looking text must keep separators for path normalize.
pub(super) fn is_windows_path_like(raw: &str) -> bool {
    raw.starts_with("\\\\")
        || (raw
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic())
            && raw.as_bytes().get(1) == Some(&b':'))
}

/// Fold unquoted shell backslash escapes (`b\ash` becomes `bash`, `\-c` becomes `-c`).
pub(super) fn decode_unquoted_word(raw: &str) -> Option<String> {
    if !raw.contains('\\') {
        return Some(raw.to_owned());
    }
    if is_windows_path_like(raw) {
        return Some(raw.to_owned());
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(chars.next()?);
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

/// Double-quote body: only `\$`, `` \` ``, `\"`, `\\`, and `\<newline>` fold.
pub(super) fn decode_double_quoted_content(content: &str) -> Option<String> {
    if !content.contains('\\') {
        return Some(content.to_owned());
    }
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(n @ ('$' | '`' | '"' | '\\' | '\n')) => out.push(n),
            Some(n) => {
                out.push('\\');
                out.push(n);
            }
            None => return None,
        }
    }
    Some(out)
}

pub(crate) fn shell_node_arg(node: Node<'_>, src: &str) -> Option<ArgText> {
    shell_node_arg_with(node, src, false)
}

/// [`shell_node_arg`]; with `fold_home` a `$HOME`/`${HOME}`-only expansion is the literal `~` (the write floor expands
/// `~` like the edit tools; read rules keep treating the word as unpinnable).
pub(super) fn shell_node_arg_with(node: Node<'_>, src: &str, fold_home: bool) -> Option<ArgText> {
    let home = |raw: String| {
        if fold_home {
            replace_home_vars(&raw)
        } else {
            None
        }
    };
    let text = || node.utf8_text(src.as_bytes()).ok().map(str::to_owned);
    match node.kind() {
        "variable_assignment" => None,
        "word" | "number" => match text().and_then(|raw| decode_unquoted_word(&raw)) {
            Some(literal) => Some(ArgText::Literal(literal)),
            None => Some(ArgText::Ambiguous),
        },
        "ansi_c_string" => {
            let raw = node.utf8_text(src.as_bytes()).ok()?;
            let body = raw.strip_prefix("$'").and_then(|s| s.strip_suffix('\''))?;
            Some(ArgText::Literal(tripwire::decode_ansi_c_body(body)))
        }
        "raw_string" => {
            let raw = node.utf8_text(src.as_bytes()).ok()?;
            let stripped = raw
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(raw);
            Some(ArgText::Literal(stripped.to_owned()))
        }
        "string" => {
            if node_has_expansion(node) {
                // `"$HOME/x"` is the literal `~/x` (P166 r7): the floor expands `~` like the edit tools do.
                let literal = text().and_then(home).and_then(|raw| {
                    let inner = raw
                        .strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(&raw);
                    decode_double_quoted_content(inner)
                });
                return Some(literal.map_or(ArgText::Ambiguous, ArgText::Literal));
            }
            let raw = node.utf8_text(src.as_bytes()).ok()?;
            let stripped = raw
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(raw);
            match decode_double_quoted_content(stripped) {
                Some(literal) => Some(ArgText::Literal(literal)),
                None => Some(ArgText::Ambiguous),
            }
        }
        "concatenation" => {
            if node_has_expansion(node) {
                let literal = text()
                    .and_then(home)
                    .and_then(|raw| decode_concatenation(&raw));
                Some(literal.map_or(ArgText::Ambiguous, ArgText::Literal))
            } else {
                match text().and_then(|raw| decode_concatenation(&raw)) {
                    Some(literal) => Some(ArgText::Literal(literal)),
                    None => Some(ArgText::Ambiguous),
                }
            }
        }
        "simple_expansion" | "expansion" => Some(
            text()
                .and_then(home)
                .map_or(ArgText::Ambiguous, ArgText::Literal),
        ),
        _ => Some(ArgText::Ambiguous),
    }
}

/// A concatenation word: when it holds a `$'...'` piece the ANSI-C decoding goes first (the plain spelling decoder
/// would read `$` and the quotes literally); otherwise the plain spelling decoder.
pub(super) fn decode_concatenation(raw: &str) -> Option<String> {
    if raw.contains("$'") {
        decode_ansi_concatenation(raw).or_else(|| decode_shell_literal_spelling(raw))
    } else {
        decode_shell_literal_spelling(raw)
    }
}

/// A concatenation that contains `$'...'` pieces (P166 r8): quote removal with the ANSI-C escapes decoded; `None` when
/// an expansion remains.
pub(super) fn decode_ansi_concatenation(raw: &str) -> Option<String> {
    if !raw.contains("$'") {
        return None;
    }
    let decoded = tripwire::decode_view(raw);
    (!decoded.contains(['$', '`'])).then_some(decoded)
}

/// `text` with every `$HOME` / `${HOME}` replaced by `~`, and (P166 r11 rule 4a) `$PWD` / `${PWD}` replaced by `~+`
/// (the tracked working directory) where a tilde word can stand: at the start of the word or right after `=`; `None`
/// when any other expansion remains, or a `$PWD` stands anywhere else.
pub(super) fn replace_home_vars(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let name_ends =
            |tail: &str| !tail.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
        let tilde_position = || {
            let before = out.trim_end_matches(['"', '\'']);
            before.is_empty() || before.ends_with('=')
        };
        if let Some(tail) = after.strip_prefix("{HOME}") {
            out.push('~');
            rest = tail;
        } else if let Some(tail) = after.strip_prefix("HOME").filter(|tail| name_ends(tail)) {
            out.push('~');
            rest = tail;
        } else if let Some(tail) = after
            .strip_prefix("{PWD}")
            .or_else(|| after.strip_prefix("PWD").filter(|tail| name_ends(tail)))
            .filter(|_| tilde_position())
        {
            out.push_str("~+");
            rest = tail;
        } else {
            return None;
        }
    }
    out.push_str(rest);
    (!out.contains(['`', '$'])).then_some(out)
}

/// Here-string and here-document nodes that feed this command's stdin: those under the redirect, pipeline or negation
/// that wraps it, and a here-document body that follows it as a sibling.
pub(super) fn stdin_bodies_around(command: Node<'_>, src: &str) -> Vec<String> {
    let mut top = command;
    while let Some(parent) = top.parent() {
        if matches!(
            parent.kind(),
            "redirected_statement" | "pipeline" | "negated_command"
        ) {
            top = parent;
        } else {
            break;
        }
    }
    let mut found = Vec::new();
    let mut stack = vec![top];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "heredoc_body" | "heredoc_redirect" | "herestring_redirect"
        ) {
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                found.push(text.to_owned());
            }
            continue;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    let mut sibling = top.next_sibling();
    while let Some(node) = sibling {
        if node.kind() != "heredoc_body" {
            break;
        }
        if let Ok(text) = node.utf8_text(src.as_bytes()) {
            found.push(text.to_owned());
        }
        sibling = node.next_sibling();
    }
    found
}

pub(super) fn shell_command_invocations(root: Node<'_>, src: &str) -> Vec<ShellInvocation> {
    shell_command_invocations_with(root, src, false)
}

pub(super) fn shell_command_invocations_with(
    root: Node<'_>,
    src: &str,
    fold_home: bool,
) -> Vec<ShellInvocation> {
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "command" {
            let mut words = Vec::new();
            let mut extras = CommandExtras::default();
            let mut globs = InvocationGlobs::default();
            for i in 0..node.named_child_count() {
                let Some(child) = node.named_child(i) else {
                    continue;
                };
                let child_text = child.utf8_text(src.as_bytes()).unwrap_or_default();
                match child.kind() {
                    "variable_assignment" => {
                        if let Some((_, value)) = child_text.split_once('=') {
                            extras.assignments.push(value.to_owned());
                        }
                    }
                    "herestring_redirect" | "heredoc_redirect" => {
                        extras.stdin_bodies.push(child_text.to_owned())
                    }
                    _ => {}
                }
                let word_node = if child.kind() == "command_name" {
                    child.named_child(0)
                } else {
                    Some(child)
                };
                // The shared normaliser decides every word it can pin down exactly (quotes, escapes, fragments,
                // unquoted braces); an unresolved word keeps the decoding below (`$HOME` folding, glob tripwires).
                let normalised = word_node
                    .filter(|node| {
                        matches!(
                            node.kind(),
                            "word" | "number" | "string" | "raw_string" | "concatenation"
                        )
                    })
                    .map(|node| {
                        crate::permission::shell_words::normalise_word_node_marking_globs(node, src)
                    });
                if let Some(Ok(list)) = normalised {
                    for word in list {
                        if word.glob != crate::permission::shell_words::GlobMark::Literal {
                            globs.patterns.insert(word.text.clone());
                        } else if shell_arg_is_ambiguous(&word.text) {
                            globs.quoted.insert(word.text.clone());
                        }
                        words.push(InvocationWord::Literal(word.text));
                    }
                    continue;
                }
                let operand =
                    word_node.and_then(|inner| shell_node_arg_with(inner, src, fold_home));
                match operand {
                    Some(ArgText::Literal(word)) => {
                        // Brace expansion makes several words (P166 r8); an unquoted spelling only, write floor only.
                        let expandable = fold_home
                            && child.kind() != "command_name"
                            && word.contains('{')
                            && (word.contains(',') || word.contains(".."))
                            && !child_text.contains(['\'', '"', '\\', '$', '`']);
                        let mut budget = tripwire::BRACE_CAP;
                        match expandable.then(|| tripwire::brace_expand(&word, &mut budget)) {
                            Some(Ok(list)) => {
                                words.extend(list.into_iter().map(InvocationWord::Literal))
                            }
                            Some(Err(())) => {
                                words.push(InvocationWord::Untrusted);
                                extras.raw_ambiguous.push(child_text.to_owned());
                            }
                            None => words.push(InvocationWord::Literal(word)),
                        }
                    }
                    Some(ArgText::Ambiguous) => {
                        words.push(InvocationWord::Untrusted);
                        if !matches!(
                            child.kind(),
                            "file_redirect"
                                | "herestring_redirect"
                                | "heredoc_redirect"
                                | "heredoc_body"
                        ) {
                            extras.raw_ambiguous.push(child_text.to_owned());
                        }
                    }
                    None => {}
                }
            }
            extras.stdin_bodies.extend(stdin_bodies_around(node, src));
            extras.git_option_untrusted = git_global_option_untrusted(&words);
            // WHY: the placeholder preserves operand indexes while preventing wrapper matches.
            let wrapper_words = words
                .iter()
                .map(|word| match word {
                    InvocationWord::Literal(word) => word.clone(),
                    InvocationWord::Untrusted => "\0".to_owned(),
                })
                .collect();
            found.push(ShellInvocation {
                start_byte: node.start_byte(),
                scope: execution_scope(node),
                words,
                wrapper_words,
                extras,
                globs,
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    found.sort_by_key(|invocation| invocation.start_byte);
    found
}

/// Auto-mode opaque-shell floor: a (potential) `-c` string reinterpretation (`bash|sh|dash|zsh|ksh -c …`) or a literal `eval` head.
/// The one classifier shared by the decomposable segment loop and the undecomposable tree walk so the two can't drift.
pub(crate) fn words_are_opaque_shell(words: &[ShellWord<'_>]) -> bool {
    shell_dash_c_script(words).is_potential_inline()
        || matches!(
            words.first(),
            Some(ShellWord::Literal(program)) if shell_program_name(program) == "eval"
        )
}

/// Undecomposable-path opaque-shell floor: word-only decomposition failed, so apply the canonical word predicate to each parsed invocation directly.
pub(crate) fn tree_has_opaque_shell(root: Node<'_>, src: &str) -> bool {
    shell_command_invocations(root, src)
        .iter()
        .any(|invocation| {
            let peeled = unwrap_invocation_checked(invocation);
            words_are_opaque_shell(&peeled.words.shell_words())
        })
}

pub(super) fn shell_redirect_targets(root: Node<'_>, src: &str) -> Vec<ShellRedirectTarget> {
    shell_redirect_targets_with(root, src, false)
}

/// [`shell_redirect_targets`]; with `fold_home` (the write floor) `$HOME` / `$PWD` fold like on command words.
pub(super) fn shell_redirect_targets_with(
    root: Node<'_>,
    src: &str,
    fold_home: bool,
) -> Vec<ShellRedirectTarget> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "file_redirect"
            && let Some((path, mode, ambiguous, raw)) = shell_redirect_one(node, src, fold_home)
        {
            out.push(ShellRedirectTarget {
                raw,
                start_byte: node.start_byte(),
                opens_at: redirect_opens_at(node),
                scope: execution_scope(node),
                path,
                mode,
                ambiguous,
            });
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                stack.push(child);
            }
        }
    }
    out
}

/// Where a redirect takes effect (P166 Grok r4 LOW 6): bash opens a statement's redirects before its body runs, so
/// `{ cd /etc; } > log` and `if cd /etc; then :; fi > log` write `log` in the old cwd. tree-sitter-bash also hangs a
/// trailing redirect on a whole `list`/`pipeline` (`cd /etc && echo > log`), where bash gives it to the LAST element
/// only, so the body is followed down to that element.
pub(super) fn redirect_opens_at(node: Node<'_>) -> usize {
    let Some(statement) = node
        .parent()
        .filter(|parent| parent.kind() == "redirected_statement")
    else {
        return node.start_byte();
    };
    let Some(mut body) = statement.child_by_field_name("body") else {
        return node.start_byte();
    };
    while matches!(body.kind(), "list" | "pipeline") {
        let Some(last) = body
            .named_child_count()
            .checked_sub(1)
            .and_then(|last| body.named_child(last))
        else {
            break;
        };
        body = last;
    }
    body.start_byte()
}

pub(super) fn shell_redirect_one(
    node: Node<'_>,
    src: &str,
    fold_home: bool,
) -> Option<(Option<String>, ShellFileMode, bool, String)> {
    let mut redirect = None;
    for i in 0..node.child_count() {
        let kind = node.child(i)?.kind();
        // `<<`/`<<<` read from inline text, not a file.
        if kind.contains("<<") {
            return None;
        }
        if kind.contains('>') || kind.contains('<') {
            redirect = Some(kind);
            break;
        }
    }
    let redirect = redirect?;
    let mode = if redirect.contains('>') {
        ShellFileMode::Write
    } else {
        ShellFileMode::Read
    };
    let duplicates_fd = matches!(redirect, ">&" | "<&");
    let dest = node.child_by_field_name("destination")?;
    let raw = dest
        .utf8_text(src.as_bytes())
        .unwrap_or_default()
        .to_owned();
    match shell_node_arg_with(dest, src, fold_home)? {
        ArgText::Literal(s) => {
            if s.is_empty()
                || s.starts_with('&')
                || (duplicates_fd && (s == "-" || s.bytes().all(|b| b.is_ascii_digit())))
            {
                None
            } else {
                let ambiguous = shell_arg_is_ambiguous(&s);
                Some((Some(s), mode, ambiguous, raw))
            }
        }
        ArgText::Ambiguous => Some((None, mode, true, raw)),
    }
}

pub(super) fn shell_sed_in_place(words: &[String]) -> bool {
    words.iter().skip(1).any(|word| {
        word == "--in-place"
            || word.starts_with("--in-place=")
            // `i` is sed's only short flag with that letter, so any `-…i…` is in-place
            || (word.starts_with('-') && !word.starts_with("--") && word.contains('i'))
    })
}

/// How a program spells its output options: `-o`, long `--output`-style options, and short-option clusters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OutputFlagSyntax {
    pub(super) clusters: ShortClusters,
    /// Long options whose value is written, matched in full or as any abbreviation down to 3 characters
    /// (`--out=f`, `--outp f`). An abbreviation that is ambiguous for the program still counts, so a match
    /// never under-reports a write.
    pub(super) long_outputs: &'static [&'static str],
    /// Long options (exact spelling) whose value is a comma list of `TYPE=PATH` items, each PATH written
    /// (`rustc --emit link=out`).
    pub(super) long_typed_outputs: &'static [&'static str],
    /// Long options (exact spelling) that take the NEXT word as their value, so that word is not rescanned as a flag
    /// (`git log --grep --out`). An abbreviation is not skipped, which can only over-report a write.
    pub(super) long_valued: &'static [&'static str],
    /// Unclustered (`Exact`) programs only: short-option letters with a mandatory value. Walking a short cluster, the
    /// first such letter takes the rest of the word, or the next word when it ends the cluster (`git log -pS --out`).
    pub(super) short_valued_letters: &'static str,
    /// Unclustered (`Exact`) programs only: letters with an optional attached value; one ends the walk without
    /// consuming the next word (`git status -uno`).
    pub(super) short_optarg_letters: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ShortClusters {
    /// Go's `flag` package: no clusters (`-json` is one flag), and `-o=FILE` means `-o FILE`.
    Go,
    /// No clusters and a literal value: only `-o`, `-o FILE` and `-oFILE` (`-o=f` writes `=f`).
    Exact,
    /// getopt-style clusters (`-no FILE` is `-n` plus `-o FILE`). Walking left to right, a letter in `arg_letters`
    /// takes the rest of the word, or the next word, as its own value; a letter in `optarg_letters` takes only the
    /// rest of the word (an optional argument never consumes the next word). Either way an `o` after it is not the
    /// output flag. Any other letter is treated as a plain flag, which over-reports a write rather than missing one.
    Getopt {
        arg_letters: &'static str,
        optarg_letters: &'static str,
    },
}

/// GNU `sort` (`-bcCdfghik:mMno:rRsS:t:T:uVy:z`): `-k`, `-S`, `-t`, `-T` and `-y` take a value.
pub(super) const SORT_OUTPUT_SYNTAX: OutputFlagSyntax = OutputFlagSyntax {
    clusters: ShortClusters::Getopt {
        arg_letters: "kStTy",
        optarg_letters: "",
    },
    long_outputs: &["--output"],
    long_typed_outputs: &[],
    long_valued: &[
        "--key",
        "--field-separator",
        "--buffer-size",
        "--temporary-directory",
        "--compress-program",
        "--files0-from",
        "--random-source",
        "--sort",
        "--parallel",
        "--batch-size",
    ],
    short_valued_letters: "",
    short_optarg_letters: "",
};
pub(super) const GO_OUTPUT_SYNTAX: OutputFlagSyntax = OutputFlagSyntax {
    clusters: ShortClusters::Go,
    long_outputs: &["--output"],
    long_typed_outputs: &[],
    long_valued: &[],
    short_valued_letters: "",
    short_optarg_letters: "",
};
/// `rustc` (getopts, which groups short options): `-C`, `-L`, `-l`, `-W`, `-A`, `-D`, `-F` and `-Z` take a value.
pub(super) const RUSTC_OUTPUT_SYNTAX: OutputFlagSyntax = OutputFlagSyntax {
    clusters: ShortClusters::Getopt {
        arg_letters: "CLlWADFZ",
        optarg_letters: "",
    },
    long_outputs: &["--output", "--out-dir"],
    long_typed_outputs: &["--emit"],
    long_valued: &[
        "--cfg",
        "--check-cfg",
        "--crate-type",
        "--crate-name",
        "--edition",
        "--print",
        "--target",
        "--cap-lints",
        "--extern",
        "--sysroot",
        "--explain",
        "--error-format",
        "--json",
        "--color",
        "--remap-path-prefix",
    ],
    short_valued_letters: "",
    short_optarg_letters: "",
};
/// `git` long options that write a file or directory, for every verb.
pub(super) const GIT_LONG_OUTPUTS: &[&str] = &["--output", "--output-directory"];
/// Free-text `git` options whose value may look like a flag.
pub(super) const GIT_LONG_VALUED: &[&str] = &[
    "--grep",
    "--author",
    "--committer",
    "--format",
    "--message",
    "--since",
    "--until",
    "--before",
    "--after",
];
/// `git` short options with a mandatory value in the log/diff family and in `grep` (`-S`, `-G`, `-I`, `-O`, `-e`).
pub(super) const GIT_SHORT_VALUED_LETTERS: &str = "SGIOe";
/// `git` short options with an optional attached value (`-M -C -B -U -X`, status `-u`).
pub(super) const GIT_SHORT_OPTARG_LETTERS: &str = "MCBUXu";
/// Global `git` options that take the next word as their value (they come before the verb).
pub(super) const GIT_GLOBALS_WITH_VALUE: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

/// Whether a global `git` option takes the next word as its value: an exact short or long name, or (like getopt_long)
/// a bare abbreviation of a long one (`--git-d /repo`). `--git-dir=/repo` carries its own value.
pub(super) fn git_global_takes_next(token: &str) -> bool {
    GIT_GLOBALS_WITH_VALUE.contains(&token)
        || (!token.contains('=')
            && GIT_GLOBALS_WITH_VALUE.iter().any(|full| {
                full.starts_with("--") && is_accepted_long_option_prefix(token, full, 3)
            }))
}

/// Index of the verb of a `git` command: the first word after the global options and their values.
/// A `--` that is not a global option's value ends the globals and the next word is the verb. (git itself rejects
/// `--` and abbreviations here; reading past them can only over-report a write.)
pub(super) fn git_verb_index(words: &[String]) -> Option<usize> {
    let mut i = 1;
    while let Some(token) = words.get(i) {
        if token == "--" {
            return words.get(i + 1).map(|_| i + 1);
        }
        if !token.starts_with('-') {
            return Some(i);
        }
        i += if git_global_takes_next(token) { 2 } else { 1 };
    }
    None
}

/// Output syntax for `git`, and the index its verb's arguments start at (global options are never rescanned).
/// `-o` is a write for every verb, and is clustered only for `archive` (every other short option is a plain flag)
/// and `format-patch`. There `-v` takes the next word even when it is `--` (git 2.50: `-v -- -o d` writes `d`); the
/// diff letters (`-U -M -C -B -l -S -G -O -X -I`) end the cluster but never take a following option word (git 2.50:
/// `-S -o d` and `-M -o d` write `d`). Other verbs keep exact `-o` so `git status -uno` stays a non-write.
/// A git alias is not resolved.
pub(super) fn git_output_syntax(words: &[String]) -> (OutputFlagSyntax, usize) {
    let verb = git_verb_index(words);
    let clusters = match verb.and_then(|i| words.get(i)).map(String::as_str) {
        Some("archive") => ShortClusters::Getopt {
            arg_letters: "",
            optarg_letters: "",
        },
        Some("format-patch") => ShortClusters::Getopt {
            arg_letters: "v",
            optarg_letters: "UMCBlSGOXI",
        },
        _ => ShortClusters::Exact,
    };
    let syntax = OutputFlagSyntax {
        clusters,
        long_outputs: GIT_LONG_OUTPUTS,
        long_typed_outputs: &[],
        long_valued: GIT_LONG_VALUED,
        short_valued_letters: GIT_SHORT_VALUED_LETTERS,
        short_optarg_letters: GIT_SHORT_OPTARG_LETTERS,
    };
    (syntax, verb.map_or(1, |i| i + 1))
}

/// Write targets of a program's output options, scanning `words` from index `start`: `-o f`, `-of`, `--output=f`,
/// `--out f` (any abbreviation of a `long_outputs` entry), `TYPE=PATH` lists of `long_typed_outputs`, and, for
/// getopt-style programs, `-o` inside a short-option cluster (`-ro f`, `-rof`).
/// Scanning stops at `--`, and a word consumed as another option's value is skipped.
/// A missing value is an empty path, so the write is still seen.
pub(super) fn shell_output_flag_values(
    words: &[String],
    syntax: OutputFlagSyntax,
    start: usize,
) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = start;
    while let Some(token) = words.get(i) {
        let next = words.get(i + 1).map(String::as_str);
        // Default: move to the next word; an option that consumes the next word moves two.
        let mut step = 1;
        if token == "--" {
            // `--` ends the options only where it cannot be the previous option's value: right after the program or
            // git verb, after an operand, after an option carrying its own `=value`, or after a getopt short cluster
            // of plain flags. After a bare long option (possibly an abbreviation such as `sort --temp`), a Go flag
            // (`-tags`) or a cluster holding a value letter (`format-patch -S --`) it may be a value, so scanning
            // goes on.
            let ends_options = i == start
                || words.get(i - 1).is_none_or(|prev| {
                    !prev.starts_with('-')
                        || prev == "-"
                        || prev.contains('=')
                        || match syntax.clusters {
                            ShortClusters::Getopt {
                                arg_letters,
                                optarg_letters,
                            } => {
                                !prev.starts_with("--")
                                    && !prev.chars().skip(1).any(|letter| {
                                        arg_letters.contains(letter)
                                            || optarg_letters.contains(letter)
                                    })
                            }
                            ShortClusters::Go | ShortClusters::Exact => false,
                        }
                });
            if ends_options {
                break;
            }
            i += 1;
            continue;
        }
        if token.starts_with("--") {
            let (flag, attached) = match token.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (token.as_str(), None),
            };
            let value = || attached.unwrap_or_else(|| next.unwrap_or(""));
            let writes = syntax
                .long_outputs
                .iter()
                .any(|full| is_accepted_long_option_prefix(flag, full, 3));
            let typed = syntax.long_typed_outputs.contains(&flag);
            if writes {
                out.push(value());
            } else if typed {
                out.extend(
                    value()
                        .split(',')
                        .filter_map(|item| item.split_once('=').map(|(_, path)| path)),
                );
            }
            if attached.is_none() && (writes || typed || syntax.long_valued.contains(&flag)) {
                step = 2;
            }
        } else if token == "-o" {
            out.push(next.unwrap_or(""));
            step = 2;
        } else if let Some(value) = token.strip_prefix("-o").filter(|value| !value.is_empty()) {
            // Glued `-oFILE`; getopt takes the rest of the word even when it starts with `-`.
            out.push(match syntax.clusters {
                ShortClusters::Go => value.strip_prefix('=').unwrap_or(value),
                ShortClusters::Exact | ShortClusters::Getopt { .. } => value,
            });
        } else if let (ShortClusters::Exact, Some(letters)) =
            (syntax.clusters, token.strip_prefix('-'))
        {
            for (at, letter) in letters.char_indices() {
                if syntax.short_optarg_letters.contains(letter) {
                    break;
                }
                if syntax.short_valued_letters.contains(letter) {
                    if at + letter.len_utf8() == letters.len() {
                        step = 2;
                    }
                    break;
                }
            }
        } else if let (
            ShortClusters::Getopt {
                arg_letters,
                optarg_letters,
            },
            Some(letters),
        ) = (syntax.clusters, token.strip_prefix('-'))
        {
            for (at, letter) in letters.char_indices() {
                let optional = optarg_letters.contains(letter);
                if letter != 'o' && !optional && !arg_letters.contains(letter) {
                    continue;
                }
                let rest = letters.get(at + letter.len_utf8()..).unwrap_or("");
                if rest.is_empty() && !optional {
                    step = 2;
                }
                if letter == 'o' {
                    out.push(if rest.is_empty() {
                        next.unwrap_or("")
                    } else {
                        rest
                    });
                }
                break;
            }
        }
        i += step;
    }
    out
}

/// Flag-named file operands (not positionals). Empty for other programs.
pub(super) fn special_file_operands(
    program: &str,
    words: &[String],
) -> Vec<(String, ShellFileMode)> {
    match program {
        "dd" => words
            .iter()
            .skip(1)
            .filter_map(|token| {
                token
                    .strip_prefix("if=")
                    .map(|path| (path.to_owned(), ShellFileMode::Read))
                    .or_else(|| {
                        token
                            .strip_prefix("of=")
                            .map(|path| (path.to_owned(), ShellFileMode::Write))
                    })
            })
            .collect(),
        // `--output`/`-o` (and git's `--output-directory`) write the output file, in every spelling the program accepts.
        // (`git`'s `-O` is a READ order-file, NOT a write, so it is intentionally excluded.)
        "sort" | "go" | "git" => {
            let (syntax, start) = match program {
                "sort" => (SORT_OUTPUT_SYNTAX, 1),
                "git" => git_output_syntax(words),
                _ => (GO_OUTPUT_SYNTAX, 1),
            };
            shell_output_flag_values(words, syntax, start)
                .into_iter()
                .map(|output| (output.to_owned(), ShellFileMode::Write))
                .collect()
        }
        // `rustc` writes its compiled output via `-o`/`--out-dir`/`--emit TYPE=PATH` (mirrors `go`).
        "rustc" => shell_output_flag_values(words, RUSTC_OUTPUT_SYNTAX, 1)
            .into_iter()
            .map(|output| (output.to_owned(), ShellFileMode::Write))
            .collect(),
        // `rustfmt` rewrites each file operand in place (like an always-on `sed -i`), so its non-flag operands are writes
        "rustfmt" => shell_file_candidates(words)
            .into_iter()
            .map(|path| (path.to_owned(), ShellFileMode::Write))
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn shell_access(mode: ShellFileMode, path: String) -> AccessKind {
    match mode {
        ShellFileMode::Read => AccessKind::Read(Some(path)),
        ShellFileMode::Write | ShellFileMode::Create => AccessKind::Edit(path),
    }
}

/// Operands that may name a file.
/// After a bare `--`, tokens are positional even if `-`-prefixed (`rm -- -/../.env`).
/// `=`-names are kept (a real `VAR=value` is already dropped by the AST).
/// u35 g3 (Astra r3): a bare `-` is an operand (stdin for most readers, a file named `-` for others) and is kept, so
/// it still holds its position: dropping it moved `uniq - README.md`'s output into the input slot.
pub(super) fn shell_file_candidates(words: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut end_of_options = false;
    for token in words.iter().skip(1) {
        if !end_of_options && token == "--" {
            end_of_options = true;
            continue;
        }
        if end_of_options || token == "-" || !token.starts_with('-') {
            out.push(token.as_str());
        }
    }
    out
}

/// u35 g3 (Astra r3): the operands of `uniq [OPTION]... [INPUT [OUTPUT]]` (GNU and BSD). The values of `-f N`, `-s N`,
/// `-w N` (attached, clustered, or as `--skip-fields N`, `--skip-chars N`, `--check-chars N` and their unique
/// prefixes) are not operands; `-` is. An obsolete `+N` is kept: it may be a skip option or a file.
pub(super) fn uniq_operands(words: &[String]) -> Vec<&str> {
    const LONG_VALUED: &[&str] = &["--skip-fields", "--skip-chars", "--check-chars"];
    let mut out = Vec::new();
    let mut end_of_options = false;
    let mut i = 1;
    while let Some(word) = words.get(i) {
        i += 1;
        let token = word.as_str();
        if end_of_options || token == "-" || !token.starts_with('-') {
            out.push(token);
            continue;
        }
        if token == "--" {
            end_of_options = true;
            continue;
        }
        if token.starts_with("--") {
            if !token.contains('=')
                && LONG_VALUED
                    .iter()
                    .any(|full| is_accepted_long_option_prefix(token, full, 3))
            {
                i += 1;
            }
            continue;
        }
        let cluster = &token[1..];
        for (at, letter) in cluster.char_indices() {
            if matches!(letter, 'f' | 's' | 'w') {
                if at + letter.len_utf8() == cluster.len() {
                    i += 1;
                }
                break;
            }
        }
    }
    out
}

/// File operands implied by path-moving commands.
/// `cp`/`mv`/`ln`/`install` read source(s) and write the destination; `rm`/`rmdir`/`mkdir`/`touch` write every operand; `None` otherwise.
/// (`chmod`/`chown` touch metadata, not content.)
pub(super) fn shell_path_command_operands<'a>(
    program: &str,
    words: &'a [String],
) -> Option<Vec<(&'a str, ShellFileMode)>> {
    match program {
        "cp" | "mv" | "ln" | "install" => {
            // Last positional is the destination (Write), the rest sources (Read).
            // The rare `-t DIR` reorder isn't parsed; bounded since denies match by basename
            let operands = shell_file_candidates(words);
            // P175b r6: `install -d` makes every operand.
            if program == "install" && install_makes_directories(words) {
                return Some(
                    operands
                        .into_iter()
                        .map(|c| (c, ShellFileMode::Write))
                        .collect(),
                );
            }
            let (dest, sources) = operands.split_last()?;
            Some(
                sources
                    .iter()
                    .map(|s| (*s, ShellFileMode::Read))
                    .chain(std::iter::once((*dest, ShellFileMode::Write)))
                    .collect(),
            )
        }
        "rm" | "rmdir" => Some(
            shell_file_candidates(words)
                .into_iter()
                .map(|c| (c, ShellFileMode::Write))
                .collect(),
        ),
        p if is_creation_program(p) => Some(
            shell_file_candidates(words)
                .into_iter()
                .map(|c| (c, ShellFileMode::Create))
                .collect(),
        ),
        // `uniq [INPUT [OUTPUT]]`: the 1st operand is the input (Read), and every later one is written (Write): GNU
        // writes the 2nd, and an obsolete `+N` read as an option shifts which word that is.
        // Fewer operands use stdin/stdout
        "uniq" => match uniq_operands(words).split_first() {
            Some((input, outputs)) if !outputs.is_empty() => Some(
                std::iter::once((*input, ShellFileMode::Read))
                    .chain(outputs.iter().map(|output| (*output, ShellFileMode::Write)))
                    .collect(),
            ),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn shell_arg_is_ambiguous(token: &str) -> bool {
    token.contains('*') || token.contains('?') || token.contains('[')
}

/// A recursive directory search can't pin its operands, so it must prompt.
/// `rg`/`ag`/`ack` recurse given no path or a directory operand (`candidates[0]` is the pattern); grep only with `-r`/`-R`.
pub(super) fn shell_reader_can_recurse(
    program: &str,
    words: &[String],
    candidates: &[&str],
) -> bool {
    let grep_recursive = matches!(program, "grep" | "egrep" | "fgrep")
        && words.iter().any(|word| {
            word == "--recursive"
                || word == "--dereference-recursive"
                || (word.starts_with('-')
                    && !word.starts_with("--")
                    && (word.contains('r') || word.contains('R')))
        });
    let searches_dir = matches!(program, "rg" | "ag" | "ack")
        && (candidates.len() <= 1 || candidates.iter().skip(1).any(|c| is_directory_operand(c)));
    grep_recursive || searches_dir
}

/// A path that syntactically names a directory (so a recursive reader descends it).
pub(super) fn is_directory_operand(token: &str) -> bool {
    token == "." || token == ".." || token.ends_with('/')
}

pub(super) fn is_absolute_shell_path(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with("~/")
        || path.as_bytes().get(1).is_some_and(|b| *b == b':')
}

pub(super) fn normalize_shell_path(path: &str) -> String {
    lexical_normalize(&normalize_shell_path_raw(path))
}

/// Quote/backslash/`/c/` normalization WITHOUT collapsing `.`/`..`.
/// Symlink resolution can then follow `..` *physically* (after the link) rather than have it erased textually before the link is ever seen.
pub(super) fn normalize_shell_path_raw(path: &str) -> String {
    let p = path.trim_matches(['\"', '\'']).replace('\\', "/");
    match p.strip_prefix("/c/") {
        Some(rest) => format!("C:/{rest}"),
        None => p,
    }
}

pub(super) fn lexical_normalize(path: &str) -> String {
    let prefix_len = if path.as_bytes().get(1).is_some_and(|b| *b == b':') {
        2
    } else {
        0
    };
    let (prefix, rest) = path.split_at(prefix_len);
    let absolute = rest.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|s| *s != "..") {
                    out.pop();
                } else if !absolute {
                    out.push("..");
                }
            }
            segment => out.push(segment),
        }
    }
    let body = out.join("/");
    match (prefix.is_empty(), absolute, body.is_empty()) {
        (false, true, false) => format!("{prefix}/{body}"),
        (false, true, true) => format!("{prefix}/"),
        (false, false, _) => format!("{prefix}{body}"),
        (true, true, false) => format!("/{body}"),
        (true, true, true) => "/".to_owned(),
        (true, false, _) => body,
    }
}
