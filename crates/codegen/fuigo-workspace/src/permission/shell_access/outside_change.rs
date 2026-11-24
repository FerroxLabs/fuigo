//! S1 (1.0.47, DS-04): the fail-safe guard on destructive changes outside the workspace.
//!
//! A destructive change (remove, move away, truncate or overwrite something that already exists) to a path outside the
//! workspace roots asks in every mode, bypass included, and is denied where no prompt can be shown. Creating a new path
//! never counts, nor does an append, except to the user-tier authority files (config, permission rules, rule files),
//! where any write counts. The only ways past the ask: a path the user typed this session (whose resolved form still
//! holds the target), a resolved path the user already approved this session, a file this session's agent created, or
//! a CLI / user-tier allow rule loaded at session start that spells the target.
//!
//! The targets come from this module's own pass over the parse ([`s1_effects`]); the shared write extractor and its
//! consumers (`targets`, `command_targets`, the protected floor) are not touched. Nothing here is persisted: every set
//! lives in memory on the session's permission handle (shared with subagents) and is empty again after a resume.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use tree_sitter::Node;

use super::*;
use crate::permission::types::{PermissionRule, RuleAction, ToolFilter};

const MAX_DEPTH: usize = 4;
const MAX_FOR_VALUES: usize = 16;
const MAX_LINK_HOPS: usize = 40;
/// A word whose value the shell computes at run time; never a path.
const UNKNOWN: &str = "\0?";
/// The cwd of a command whose wrapper moved it to a directory the guard cannot read back (`sudo -i`, `chroot`).
const MOVED: &str = "/\0moved";

/// What an effect does to its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EffectKind {
    Remove,
    Overwrite,
    Create,
    Append,
    /// A hard link is made to the path: only judged against the authority files.
    Alias,
    /// The script (or a nested `sh -c` script) did not parse: its effects cannot be known, so it asks (fail safe).
    Unparsed,
}

/// How the final component is treated: the name itself (`rm`, `mv`, a replacing `ln -f`), what it points to (`>`,
/// `cp`, `truncate`), or both when the program's behaviour is not modelled (`rsync`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Final {
    Entry,
    Follow,
    Both,
}

/// One effect of a command on one path, with the cwd already applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct S1Effect {
    /// Absolute, as spelled (joined to its cwd, not normalised).
    pub(crate) path: PathBuf,
    pub(crate) kind: EffectKind,
    pub(crate) fin: Final,
    /// The decoded words of the command that performs it, for the pre-allow rule match.
    pub(crate) segment: String,
    /// Links made earlier in the same command line (A8): `(link, what it points to)`, both absolute.
    pub(crate) links: Vec<(PathBuf, PathBuf)>,
    /// The path stands for what lies under it (a glob's parent, a `find` start): never remembered as an approval.
    pub(crate) wide: bool,
}

// ───────────────────────────── the S1-only extractor ─────────────────────────────

/// Every destructive, creating or appending effect of a shell script run in `exec_dir`.
pub(crate) fn s1_effects(src: &str, exec_dir: &Path, home: Option<&Path>) -> Vec<S1Effect> {
    let mut walk = Walk { out: Vec::new() };
    let mut st = St::start(exec_dir, home);
    walk.script(src, exec_dir, &mut st, MAX_DEPTH);
    let mut out = walk.out;
    out.dedup();
    out
}

#[derive(Clone)]
struct St {
    /// The cwds the next command can run in; `None` when a `cd` could not be pinned.
    cwds: Vec<Option<PathBuf>>,
    /// Same-line assignments (and `HOME`), substituted into words.
    vars: HashMap<String, String>,
    /// The `pushd` stack: the cwds each `popd` returns to.
    stack: Vec<Vec<Option<PathBuf>>>,
    links: Vec<(PathBuf, PathBuf)>,
    home: Option<PathBuf>,
    /// The cwds before the last `cd`, which may have failed: in a `;` sequence the next statement may run in either.
    fallback: Option<Vec<Option<PathBuf>>>,
}

impl St {
    /// After a statement in a sequence (or a conditional body), a `cd` that may have failed leaves either cwd.
    fn settle(&mut self) {
        for cwd in self.fallback.take().unwrap_or_default() {
            if !self.cwds.contains(&cwd) {
                self.cwds.push(cwd);
            }
        }
    }

    fn start(exec_dir: &Path, home: Option<&Path>) -> Self {
        let mut vars = HashMap::new();
        if let Some(home) = home {
            vars.insert("HOME".to_owned(), home.to_string_lossy().into_owned());
        }
        Self {
            cwds: vec![Some(exec_dir.to_path_buf())],
            vars,
            stack: Vec::new(),
            links: Vec::new(),
            home: home.map(Path::to_path_buf),
            fallback: None,
        }
    }

    /// Either state may hold afterwards (`a || b`, a conditional body).
    fn merge(&mut self, other: St) {
        for cwd in other.cwds {
            if !self.cwds.contains(&cwd) {
                self.cwds.push(cwd);
            }
        }
        // A name set on one path only keeps its value: unset expands to nothing, which names no target.
        self.vars
            .retain(|name, value| other.vars.get(name).is_none_or(|v| v == value));
        for (name, value) in other.vars {
            self.vars.entry(name).or_insert(value);
        }
        for link in other.links {
            if !self.links.contains(&link) {
                self.links.push(link);
            }
        }
        // Stack levels merge like cwds; a level only one side has becomes unknown.
        let depth = self.stack.len().max(other.stack.len());
        self.stack.resize(depth, vec![None]);
        for (level, theirs) in self
            .stack
            .iter_mut()
            .zip(other.stack.into_iter().chain(std::iter::repeat(vec![None])))
        {
            for cwd in theirs {
                if !level.contains(&cwd) {
                    level.push(cwd);
                }
            }
        }
    }

    /// The state a child shell (`sh -c`) starts with: same cwd and links, only `HOME` known.
    fn child(&self) -> Self {
        let mut child = self.clone();
        child.vars.retain(|name, _| name == "HOME");
        child
    }
}

struct Walk {
    out: Vec<S1Effect>,
}

/// One decoded word, and whether it is an unquoted glob.
type Word = Option<(String, bool)>;

impl Walk {
    /// Parse and walk one script. A script that does not parse cannot be judged, so it counts as an outside change
    /// (fail safe: a boundary, not a list of forms).
    fn script(&mut self, src: &str, exec_dir: &Path, st: &mut St, depth: usize) {
        let tree = try_parse_shell(src);
        if let Some(tree) = &tree {
            self.node(tree.root_node(), src, st, depth);
        }
        if tree.as_ref().is_none_or(|t| t.root_node().has_error()) {
            self.unparsed(exec_dir, src);
        }
    }

    /// Effects that cannot be known: the request asks (fail safe).
    fn unparsed(&mut self, dir: &Path, segment: &str) {
        self.out.push(S1Effect {
            path: dir.to_path_buf(),
            kind: EffectKind::Unparsed,
            fin: Final::Entry,
            segment: segment.to_owned(),
            links: Vec::new(),
            wide: false,
        });
    }

    /// Statements in sequence: after a `cd` that may have failed, the next one may run in the old cwd too (Astra H1).
    fn seq(&mut self, node: Node<'_>, src: &str, st: &mut St, depth: usize) {
        for child in named_children(node) {
            self.node(child, src, st, depth);
            st.settle();
        }
    }

    /// The commands inside `$(...)`, backticks, `<(...)` and `>(...)` anywhere below `node` (a word, an assignment,
    /// a redirect, a heredoc body) are walked like any other command, in a copy of the state.
    fn subs(&mut self, node: Node<'_>, src: &str, st: &St, depth: usize) {
        if matches!(node.kind(), "command_substitution" | "process_substitution") {
            self.node(node, src, &mut st.clone(), depth);
            return;
        }
        for child in named_children(node) {
            self.subs(child, src, st, depth);
        }
    }

    fn node(&mut self, node: Node<'_>, src: &str, st: &mut St, depth: usize) {
        match node.kind() {
            "comment" | "heredoc_start" | "heredoc_end" => {}
            // An unquoted heredoc body expands its substitutions; a quoted one has none.
            "heredoc_body" => self.subs(node, src, st, depth),
            "command" => {
                self.command(node, None, src, st, depth, None);
            }
            "variable_assignment" => {
                self.subs(node, src, st, depth);
                assign(node, src, st);
            }
            "declaration_command" => {
                self.subs(node, src, st, depth);
                for child in named_children(node) {
                    if child.kind() == "variable_assignment" {
                        assign(child, src, st);
                    }
                }
            }
            "redirected_statement" => {
                let body = node.child_by_field_name("body");
                let list_body = body.is_some_and(|b| b.kind() == "list");
                // bash opens a statement's redirects before its body; a trailing redirect on a list belongs to its
                // last element, which runs in the cwd the list ends in.
                if !list_body {
                    self.redirects(node, src, st);
                }
                match body {
                    Some(body) if body.kind() == "command" => {
                        self.command(body, Some(node), src, st, depth, None);
                    }
                    Some(body) => self.node(body, src, st, depth),
                    None => {}
                }
                if list_body {
                    self.redirects(node, src, st);
                }
            }
            "list" => {
                let or = has_or(node);
                let parts = if or {
                    named_children(node).collect()
                } else {
                    and_chain(node)
                };
                let Some((first, rest)) = parts.split_first() else {
                    return;
                };
                let before = st.clone();
                self.node(*first, src, st, depth);
                let after_first = st.clone();
                if or {
                    // The right side runs when the left side failed, so in either state.
                    let mut alt = before;
                    alt.merge(after_first.clone());
                    for part in rest {
                        self.node(*part, src, &mut alt, depth);
                    }
                    *st = after_first;
                    st.merge(alt);
                } else {
                    // `a && b`: b runs only on a's success path; afterwards either exit may hold.
                    let mut exits = before;
                    exits.merge(after_first);
                    for part in rest {
                        exits.merge(st.clone());
                        // It runs only if the left side, a `cd` included, succeeded.
                        st.fallback = None;
                        self.node(*part, src, st, depth);
                    }
                    st.merge(exits);
                }
            }
            "pipeline" => {
                let mut names: Option<Vec<String>> = None;
                for part in named_children(node) {
                    let mut sub = st.clone();
                    names = match part.kind() {
                        "command" => self.command(part, None, src, &mut sub, depth, names.take()),
                        "redirected_statement" => {
                            self.redirects(part, src, &sub);
                            match part.child_by_field_name("body") {
                                Some(body) if body.kind() == "command" => self.command(
                                    body,
                                    Some(part),
                                    src,
                                    &mut sub,
                                    depth,
                                    names.take(),
                                ),
                                Some(body) => {
                                    self.node(body, src, &mut sub, depth);
                                    None
                                }
                                None => None,
                            }
                        }
                        _ => {
                            self.node(part, src, &mut sub, depth);
                            None
                        }
                    };
                }
            }
            "subshell" | "command_substitution" | "process_substitution" => {
                self.seq(node, src, &mut st.clone(), depth);
            }
            "for_statement" => self.for_loop(node, src, st, depth),
            "if_statement" | "case_statement" => self.branches(node, src, st, depth),
            "while_statement"
            | "until_statement"
            | "function_definition"
            | "c_style_for_statement" => {
                let before = st.clone();
                self.seq(node, src, st, depth);
                st.merge(before);
            }
            _ => self.seq(node, src, st, depth),
        }
    }

    /// `if` and `case`: the condition (or the `case` word) runs first; then exactly one branch runs, each from that
    /// same state, so one branch's `cd` never moves another (Astra H3). Afterwards any branch's exit, or none, may hold.
    fn branches(&mut self, node: Node<'_>, src: &str, st: &mut St, depth: usize) {
        let mut entry: Option<St> = None;
        let mut exits: Vec<St> = Vec::new();
        let mut then = None::<St>;
        for i in 0..node.named_child_count() {
            let Some(child) = node.named_child(i) else {
                continue;
            };
            let field = node.field_name_for_named_child(i as u32);
            let branch = matches!(child.kind(), "elif_clause" | "else_clause" | "case_item");
            if !branch && (field == Some("condition") || field == Some("value")) {
                self.node(child, src, st, depth);
                continue;
            }
            let start = entry.get_or_insert_with(|| st.clone()).clone();
            if branch {
                if let Some(done) = then.take() {
                    exits.push(done);
                }
                let mut b = start;
                for part in named_children(child) {
                    self.node(part, src, &mut b, depth);
                    b.settle();
                }
                exits.push(b);
            } else {
                // A statement of the `then` body.
                let mut b = then.take().unwrap_or(start);
                self.node(child, src, &mut b, depth);
                b.settle();
                then = Some(b);
            }
        }
        exits.extend(then);
        for exit in exits {
            st.merge(exit);
        }
    }

    /// A literal for-list is as pinned as a same-line assignment (`for f in /srv/data/app.db; do rm -f "$f"; done`).
    fn for_loop(&mut self, node: Node<'_>, src: &str, st: &mut St, depth: usize) {
        let name = node
            .child_by_field_name("variable")
            .and_then(|n| n.utf8_text(src.as_bytes()).ok())
            .map(str::to_owned);
        let mut values: Option<Vec<String>> = Some(Vec::new());
        let mut body = None;
        for i in 0..node.named_child_count() {
            let Some(child) = node.named_child(i) else {
                continue;
            };
            if node.field_name_for_named_child(i as u32) == Some("value") {
                self.subs(child, src, st, depth);
                match decode_node(child, src, st) {
                    Some(words) if words.iter().all(|(_, glob)| !glob) => {
                        if let Some(values) = values.as_mut() {
                            values.extend(words.into_iter().map(|(w, _)| w));
                        }
                    }
                    _ => values = None,
                }
            } else if child.kind() == "do_group" {
                body = Some(child);
            }
        }
        let (Some(name), Some(body)) = (name, body) else {
            return;
        };
        let before = st.clone();
        match values.filter(|v| !v.is_empty() && v.len() <= MAX_FOR_VALUES) {
            Some(values) => {
                for value in values {
                    st.vars.insert(name.clone(), value);
                    self.node(body, src, st, depth);
                }
            }
            None => {
                st.vars.remove(&name);
                self.node(body, src, st, depth);
            }
        }
        st.merge(before);
    }

    fn redirects(&mut self, statement: Node<'_>, src: &str, st: &St) {
        for child in named_children(statement) {
            match child.kind() {
                "file_redirect" => self.redirect(child, statement, src, st),
                "heredoc_redirect" | "herestring_redirect" => self.subs(child, src, st, MAX_DEPTH),
                _ => {}
            }
        }
    }

    fn redirect(&mut self, node: Node<'_>, statement: Node<'_>, src: &str, st: &St) {
        // Any redirect's target may hold a substitution (`cat <(rm ...)`, `> "$(rm ...)"`).
        self.subs(node, src, st, MAX_DEPTH);
        let Some(op) = (0..node.child_count())
            .filter_map(|i| node.child(i))
            .map(|c| c.kind())
            .find(|k| k.contains('>') || k.contains('<'))
        else {
            return;
        };
        let kind = match op {
            ">" | ">|" | "&>" | ">&" => EffectKind::Overwrite,
            ">>" | "&>>" => EffectKind::Append,
            _ => return,
        };
        let Some(dest) = node.child_by_field_name("destination") else {
            return;
        };
        let Some(words) = decode_node(dest, src, st) else {
            return;
        };
        let [(path, glob)] = words.as_slice() else {
            return;
        };
        if path.is_empty()
            || (op == ">&" && (path == "-" || path.bytes().all(|b| b.is_ascii_digit())))
        {
            return;
        }
        let segment = statement
            .utf8_text(src.as_bytes())
            .unwrap_or_default()
            .to_owned();
        let cmd = Cmd {
            cwds: &st.cwds,
            segment: &segment,
            links: &st.links,
        };
        self.emit(&cmd, path, *glob, kind, Final::Follow);
    }

    /// One simple command; returns the names it prints when it is a pipeline producer (`echo`, `printf`, `find`).
    fn command(
        &mut self,
        node: Node<'_>,
        statement: Option<Node<'_>>,
        src: &str,
        st: &mut St,
        depth: usize,
        xargs_names: Option<Vec<String>>,
    ) -> Option<Vec<String>> {
        let mut words: Vec<Word> = Vec::new();
        // A prefix assignment (`D=/srv/data rm -f "$D/app.db"`) is assumed to reach the command's words (Grok H1):
        // the fail-safe reading, since the guard does not model which expansions see it.
        let mut local = st.clone();
        for child in named_children(node) {
            if child.kind() == "variable_assignment" {
                assign(child, src, &mut local);
            }
        }
        let decoded = &local;
        for child in named_children(node) {
            if child.kind() != "file_redirect" {
                self.subs(child, src, st, depth);
            }
            match child.kind() {
                "variable_assignment" | "herestring_redirect" | "heredoc_redirect" => {}
                "file_redirect" => self.redirect(child, node, src, st),
                "command_name" => {
                    let inner = child.named_child(0).unwrap_or(child);
                    push_words(&mut words, decode_node(inner, src, decoded));
                }
                _ => push_words(&mut words, decode_node(child, src, decoded)),
            }
        }
        let lit: Vec<String> = words
            .iter()
            .map(|w| {
                w.as_ref()
                    .map_or_else(|| UNKNOWN.to_owned(), |(t, _)| t.clone())
            })
            .collect();
        let peel = peel_write_command(&lit);
        if peel.opaque {
            // The wrapper hides the command it runs (`env -S`, `flock -c`): it cannot be judged, so it asks (Grok H2).
            let dir = st.cwds.iter().flatten().next().cloned().unwrap_or_default();
            self.unparsed(&dir, &lit.join(" "));
            return None;
        }
        let inner = peel.words;
        let offset = lit.len().checked_sub(inner.len())?;
        let globs: Vec<bool> = words[offset..]
            .iter()
            .map(|w| w.as_ref().is_some_and(|(_, glob)| *glob))
            .collect();
        let program = shell_program_name(inner.first()?).to_ascii_lowercase();
        if program == UNKNOWN {
            return None;
        }
        let segment = lit.join(" ");
        // A wrapper that moves the cwd (`env -C DIR`, `sudo -D DIR`) runs the command there; when the directory
        // cannot be read back, its relative targets are judged at MOVED and ask (Grok H2).
        let mut moved = peel.moved.then(|| {
            let mut moved = st.clone();
            moved.cwds = match moved_dirs(&lit[..offset]) {
                Some(dirs) => dirs.iter().fold(st.cwds.clone(), |cwds, dir| {
                    cwds.iter()
                        .map(|cwd| absolute(cwd.as_deref(), dir))
                        .collect()
                }),
                None => vec![Some(PathBuf::from(MOVED))],
            };
            moved
        });
        let from = self.out.len();
        let names = {
            let st: &mut St = match moved.as_mut() {
                Some(moved) => moved,
                None => &mut *st,
            };
            let cmd = Cmd {
                cwds: &st.cwds,
                segment: &segment,
                links: &st.links,
            };
            match program.as_str() {
                "cd" => {
                    change_dir(inner, st);
                    None
                }
                // The directory stack (Astra H3): `pushd DIR` saves the cwd, `pushd` alone swaps, `popd` returns; any
                // `+N`/`-N` form is not modelled and leaves the cwd unpinned.
                "pushd" => {
                    let saved = st.cwds.clone();
                    match &inner[1..] {
                        [] => st.cwds = st.stack.pop().unwrap_or_else(|| vec![None]),
                        [w] if w.starts_with(['+', '-']) => st.cwds = vec![None],
                        _ => change_dir(inner, st),
                    }
                    st.stack.push(saved);
                    None
                }
                "popd" => {
                    st.cwds = match &inner[1..] {
                        [] => st.stack.pop().unwrap_or_else(|| vec![None]),
                        _ => vec![None],
                    };
                    None
                }
                "echo" => Some(
                    inner[1..]
                        .iter()
                        .skip_while(|w| matches!(w.as_str(), "-n" | "-e" | "-E"))
                        .flat_map(|w| w.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
                        .collect(),
                ),
                "printf" => {
                    let args: Vec<&String> = inner[1..].iter().skip_while(|w| *w == "--").collect();
                    (args.first().is_some_and(|w| !w.starts_with('-')) && args.len() > 1).then(
                        || {
                            args[1..]
                                .iter()
                                .flat_map(|w| {
                                    w.split_whitespace().map(str::to_owned).collect::<Vec<_>>()
                                })
                                .collect()
                        },
                    )
                }
                "find" => {
                    let cmd = cmd.owned();
                    Some(self.find(&inner[1..], &cmd, st))
                }
                "xargs" => {
                    if let (Some(names), Some(run)) = (xargs_names, xargs_command(inner)) {
                        let mut argv = run.to_vec();
                        let globs = vec![false; argv.len() + names.len()];
                        argv.extend(names);
                        let cmd = cmd.owned();
                        self.classify(&argv, &globs, &cmd.borrow(), st);
                    }
                    None
                }
                "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" => {
                    self.nested_shell(inner, statement, src, st, depth);
                    None
                }
                _ => {
                    let cmd = cmd.owned();
                    self.classify(inner, &globs, &cmd.borrow(), st);
                    None
                }
            }
        };
        if let Some(moved) = moved {
            st.links = moved.links;
            let tail = self.out.split_off(from);
            let n = tail.len();
            self.out
                .extend(tail.into_iter().filter(|e| !e.path.starts_with(MOVED)));
            if self.out.len() < from + n {
                self.unparsed(Path::new(MOVED), &segment);
            }
        }
        names
    }

    /// `sh -c 'script'` and a quoted heredoc fed to a shell: the script is parsed and judged in the same cwd.
    fn nested_shell(
        &mut self,
        inner: &[String],
        statement: Option<Node<'_>>,
        src: &str,
        st: &St,
        depth: usize,
    ) {
        let mut script = None;
        let mut has_operand = false;
        let mut i = 1;
        while let Some(word) = inner.get(i) {
            if word.starts_with('-') && !word.starts_with("--") && word[1..].contains('c') {
                script = inner.get(i + 1).cloned();
                break;
            }
            if !word.starts_with('-') && !word.starts_with('+') {
                has_operand = true;
                break;
            }
            i += 1;
        }
        let script = match script {
            Some(script) => Some(script),
            None if !has_operand => statement.and_then(|s| quoted_heredoc_body(s, src)),
            None => None,
        };
        let Some(script) = script.filter(|s| s != UNKNOWN) else {
            return;
        };
        let dir = st.cwds.iter().flatten().next().cloned().unwrap_or_default();
        // Nested deeper than the guard follows: not judged, so it asks (Grok M3).
        let Some(depth) = depth.checked_sub(1) else {
            self.unparsed(&dir, &script);
            return;
        };
        let mut child = st.child();
        self.script(&script, &dir, &mut child, depth);
    }

    /// `find START... EXPR`: `-delete` removes the START points; a deleter run by `-exec` acts on the START points only
    /// through `{}`, and its fixed operands are judged on their own (only absolute ones for `-execdir`).
    fn find(&mut self, args: &[String], cmd: &OwnedCmd, st: &mut St) -> Vec<String> {
        let mut i = 0;
        while let Some(word) = args.get(i) {
            match word.as_str() {
                "-H" | "-L" | "-P" => i += 1,
                "-D" => i += 2,
                w if w.starts_with("-O") => i += 1,
                _ => break,
            }
        }
        let mut starts = Vec::new();
        while let Some(word) = args.get(i) {
            if word.starts_with('-') || matches!(word.as_str(), "(" | "!" | ",") {
                break;
            }
            starts.push(word.clone());
            i += 1;
        }
        if starts.is_empty() {
            starts.push(".".to_owned());
        }
        let depth_zero = args[i..]
            .windows(2)
            .any(|w| w[0] == "-maxdepth" && w[1] == "0");
        while let Some(word) = args.get(i) {
            i += 1;
            match word.as_str() {
                "-delete" => {
                    let from = self.out.len();
                    for start in &starts {
                        self.emit(
                            &cmd.borrow(),
                            start,
                            false,
                            EffectKind::Remove,
                            Final::Entry,
                        );
                    }
                    self.widen_from(from);
                }
                "-exec" | "-execdir" | "-ok" | "-okdir" => {
                    let begin = i;
                    while args.get(i).is_some_and(|w| w != ";" && w != "+") {
                        i += 1;
                    }
                    let run = &args[begin..i.min(args.len())];
                    i += 1;
                    let in_dir = word.ends_with("dir");
                    // `-execdir` runs in the directory of each match: the START point's parent for the START itself,
                    // the START or a directory below it for deeper matches (Astra H4).
                    let mut entry_dirs: Vec<Option<PathBuf>> = Vec::new();
                    if in_dir {
                        for cwd in &cmd.cwds {
                            for start in &starts {
                                let abs = absolute(cwd.as_deref(), start)
                                    .map(|p| fuigo_paths::normalize_lexically(&p));
                                for dir in [
                                    abs.as_ref().and_then(|p| p.parent()).map(Path::to_path_buf),
                                    abs.clone(),
                                ] {
                                    if !entry_dirs.contains(&dir) {
                                        entry_dirs.push(dir);
                                    }
                                }
                            }
                        }
                    }
                    let sub = Cmd {
                        cwds: if in_dir { &entry_dirs } else { &cmd.cwds },
                        segment: &cmd.segment,
                        links: &cmd.links,
                    };
                    let globs = vec![false; run.len()];
                    if run.iter().any(|w| w.contains("{}")) {
                        for start in &starts {
                            let argv: Vec<String> =
                                run.iter().map(|w| w.replace("{}", start)).collect();
                            // Inherited START points resolve in find's cwd even for `-execdir`.
                            let start_cmd = Cmd {
                                cwds: &cmd.cwds,
                                ..sub
                            };
                            self.classify(
                                &argv,
                                &globs,
                                if in_dir { &start_cmd } else { &sub },
                                st,
                            );
                        }
                    } else {
                        let from = self.out.len();
                        self.classify(run, &globs, &sub, st);
                        // Below depth 0 the match directories are not known: a fixed relative operand changes something
                        // under a START point, so the START counts as changed (fail safe).
                        let relative = run.iter().skip(1).any(|w| !w.starts_with(['/', '-']));
                        if in_dir && relative && self.out.len() > from && !depth_zero {
                            let wide = self.out.len();
                            for start in &starts {
                                self.emit(
                                    &cmd.borrow(),
                                    start,
                                    false,
                                    EffectKind::Remove,
                                    Final::Follow,
                                );
                            }
                            self.widen_from(wide);
                        }
                    }
                }
                _ => {}
            }
        }
        starts
    }

    /// The effects of one program's argv (`argv[0]` is the program).
    fn classify(&mut self, argv: &[String], globs: &[bool], cmd: &Cmd<'_>, st: &mut St) {
        let Some(head) = argv.first() else { return };
        let program = shell_program_name(head).to_ascii_lowercase();
        let args = &argv[1..];
        let glob_at = |i: usize| globs.get(i + 1).copied().unwrap_or(false);
        match program.as_str() {
            "rm" | "unlink" | "rmdir" => {
                let a = Args::parse(args, "", &[]);
                for i in a.operands {
                    self.emit(cmd, &args[i], glob_at(i), EffectKind::Remove, Final::Entry);
                }
            }
            "shred" => {
                let a = Args::parse(args, "ns", &["iterations", "size", "random-source"]);
                let remove = a.has('u') || a.has_long_prefix("remove");
                for i in &a.operands {
                    self.emit(
                        cmd,
                        &args[*i],
                        glob_at(*i),
                        EffectKind::Overwrite,
                        Final::Follow,
                    );
                    if remove {
                        self.emit(
                            cmd,
                            &args[*i],
                            glob_at(*i),
                            EffectKind::Remove,
                            Final::Entry,
                        );
                    }
                }
            }
            "truncate" => {
                let a = Args::parse(args, "sr", &["size", "reference"]);
                for i in a.operands {
                    self.emit(
                        cmd,
                        &args[i],
                        glob_at(i),
                        EffectKind::Overwrite,
                        Final::Follow,
                    );
                }
            }
            "tee" => {
                let a = Args::parse(args, "", &["output-error"]);
                let kind = if a.has('a') || a.has_long("append") {
                    EffectKind::Append
                } else {
                    EffectKind::Overwrite
                };
                for i in a.operands {
                    self.emit(cmd, &args[i], glob_at(i), kind, Final::Follow);
                }
            }
            "dd" => {
                for arg in args {
                    if let Some(path) = arg.strip_prefix("of=") {
                        self.emit(cmd, path, false, EffectKind::Overwrite, Final::Follow);
                    }
                }
            }
            // `cp -l`/`--link` and `cp -s`/`--symbolic-link` make links, judged like `ln` (Grok H1).
            "cp" if {
                let a = Args::parse(args, "tS", &["target-directory", "suffix"]);
                a.has('l') || a.has('s') || a.has_long("link") || a.has_long("symbolic-link")
            } =>
            {
                let ln_args: Vec<String> = args
                    .iter()
                    .filter(|w| *w != "--link")
                    .map(|w| {
                        if w == "--symbolic-link" {
                            "-s".to_owned()
                        } else {
                            w.clone()
                        }
                    })
                    .collect();
                self.ln(&ln_args, cmd, st);
            }
            "mv" | "cp" | "install" | "ginstall" => self.copy_like(&program, args, globs, cmd),
            "ln" => self.ln(args, cmd, st),
            // Recorded so that later cleanup of what the agent made stays quiet (Fable M8, Astra H1).
            "mkdir" | "touch" => {
                let a = Args::parse(
                    args,
                    "mdrtZ",
                    &["mode", "date", "reference", "time", "context"],
                );
                for i in a.operands {
                    self.emit(cmd, &args[i], glob_at(i), EffectKind::Create, Final::Follow);
                }
            }
            "sed" | "gsed" if shell_sed_in_place(argv) => {
                let a = Args::parse(args, "efl", &["expression", "file", "line-length"]);
                let scripted =
                    a.has('e') || a.has('f') || a.has_long("expression") || a.has_long("file");
                // GNU and BSD sed -i write a new file and rename it over the name: a link is replaced, not followed.
                let fin = if a.has_long("follow-symlinks") {
                    Final::Follow
                } else {
                    Final::Entry
                };
                for i in a.operands.iter().skip(usize::from(!scripted)) {
                    self.emit(cmd, &args[*i], glob_at(*i), EffectKind::Overwrite, fin);
                }
            }
            "perl" | "ruby" => {
                let a = Args::parse(args, "eEIMx", &[]);
                let in_place = args
                    .iter()
                    .take_while(|w| w.starts_with('-') && *w != "--")
                    .any(|w| {
                        !w.starts_with("--")
                            && w[1..]
                                .split(['e', 'E', 'I', 'M', 'x'])
                                .next()
                                .is_some_and(|c| c.contains('i'))
                    });
                if in_place {
                    let scripted = a.has('e') || a.has('E');
                    for i in a.operands.iter().skip(usize::from(!scripted)) {
                        self.emit(
                            cmd,
                            &args[*i],
                            glob_at(*i),
                            EffectKind::Overwrite,
                            Final::Entry,
                        );
                    }
                }
            }
            "rsync" => {
                let a = Args::parse(
                    args,
                    "efT",
                    &[
                        "rsh",
                        "exclude",
                        "include",
                        "filter",
                        "files-from",
                        "temp-dir",
                        "partial-dir",
                        "backup-dir",
                        "suffix",
                        "chmod",
                        "chown",
                        "log-file",
                        "password-file",
                        "rsync-path",
                        "compare-dest",
                        "link-dest",
                        "copy-dest",
                        "exclude-from",
                        "include-from",
                    ],
                );
                let Some((dest, sources)) = a.operands.split_last() else {
                    return;
                };
                let dest = &args[*dest];
                if remote_spec(dest) {
                    return;
                }
                if a.has_long_prefix("del") {
                    self.emit(cmd, dest, false, EffectKind::Remove, Final::Follow);
                }
                let named: Vec<&str> = sources
                    .iter()
                    .map(|i| args[*i].as_str())
                    .filter(|s| !s.ends_with('/') && !remote_spec(s))
                    .collect();
                self.emit_dest(cmd, dest, &named, false, EffectKind::Overwrite, Final::Both);
            }
            "tar" | "gtar" | "bsdtar" => self.tar(args, cmd),
            "unzip" => {
                let a = Args::parse(args, "dPx", &[]);
                let dir = a.value('d').unwrap_or_else(|| ".".to_owned());
                for i in a.operands.iter().skip(1) {
                    let member = join_text(&dir, &args[*i]);
                    self.emit(
                        cmd,
                        &member,
                        glob_at(*i),
                        EffectKind::Overwrite,
                        Final::Follow,
                    );
                }
            }
            _ => {}
        }
    }

    /// `mv`, `cp`, `install`: a source of `mv` is removed; the destination (or `DIR/basename(src)` for an existing
    /// directory) is replaced by `mv` and `install` and written through by `cp` (unless `--remove-destination`).
    fn copy_like(&mut self, program: &str, args: &[String], globs: &[bool], cmd: &Cmd<'_>) {
        let a = Args::parse(
            args,
            if program == "cp" { "tS" } else { "tSgmo" },
            &[
                "target-directory",
                "suffix",
                "group",
                "mode",
                "owner",
                "strip-program",
            ],
        );
        if program != "mv" && program != "cp" && a.has('d') {
            return;
        }
        let no_target_dir = a.has('T') || a.has_long("no-target-directory");
        let (dest, sources): (String, Vec<usize>) =
            match a.value('t').or_else(|| a.long_value("target-directory")) {
                Some(dir) => (dir, a.operands.clone()),
                None => match a.operands.split_last() {
                    Some((dest, sources)) if !sources.is_empty() => {
                        (args[*dest].clone(), sources.to_vec())
                    }
                    _ => return,
                },
            };
        if program == "mv" {
            for i in &sources {
                let glob = globs.get(i + 1).copied().unwrap_or(false);
                self.emit(cmd, &args[*i], glob, EffectKind::Remove, Final::Entry);
            }
        }
        let fin = if program == "cp" && !a.has_long("remove-destination") {
            Final::Follow
        } else {
            Final::Entry
        };
        let names: Vec<&str> = sources.iter().map(|i| args[*i].as_str()).collect();
        self.emit_dest(
            cmd,
            &dest,
            &names,
            no_target_dir,
            EffectKind::Overwrite,
            fin,
        );
    }

    /// `ln`: a forced link replaces an existing name (an Entry overwrite); every link made is applied as a virtual link
    /// to the later effects of the same line (A8); a hard link's source is judged against the authority files.
    fn ln(&mut self, args: &[String], cmd: &Cmd<'_>, st: &mut St) {
        let a = Args::parse(args, "tS", &["target-directory", "suffix"]);
        let symbolic = a.has('s') || a.has_long("symbolic");
        let force = a.has('f') || a.has_long("force");
        let no_deref = a.has('T')
            || a.has('n')
            || a.has_long("no-target-directory")
            || a.has_long("no-dereference");
        let ops: Vec<&str> = a.operands.iter().map(|i| args[*i].as_str()).collect();
        let (targets, link_dir, link): (Vec<&str>, Option<String>, Option<&str>) =
            match a.value('t').or_else(|| a.long_value("target-directory")) {
                Some(dir) => (ops.clone(), Some(dir), None),
                None => match ops.as_slice() {
                    [] => return,
                    [only] => (vec![*only], Some(".".to_owned()), None),
                    [targets @ .., link] => (targets.to_vec(), None, Some(*link)),
                },
            };
        for cwd in cmd.cwds.iter() {
            for target in &targets {
                let link_text = match (&link_dir, link) {
                    (Some(dir), _) => join_text(dir, basename(target)),
                    (None, Some(link)) => link.to_owned(),
                    (None, None) => continue,
                };
                let Some(mut link_abs) = absolute(cwd.as_deref(), &link_text) else {
                    continue;
                };
                if link_dir.is_none()
                    && !no_deref
                    && std::fs::metadata(&link_abs).is_ok_and(|m| m.is_dir())
                {
                    link_abs = link_abs.join(basename(target));
                }
                if force {
                    self.push(link_abs.clone(), EffectKind::Overwrite, Final::Entry, cmd);
                } else {
                    // Without `-f`, `ln` fails on an existing name and links nothing (Astra H2), unless an earlier
                    // command of the line removed or moved that name away (Fable M); a new link is a creation.
                    let gone = self.out.iter().any(|e| {
                        e.kind == EffectKind::Remove
                            && fuigo_paths::normalize_lexically(&e.path)
                                == fuigo_paths::normalize_lexically(&link_abs)
                    });
                    if !gone && std::fs::symlink_metadata(&link_abs).is_ok() {
                        continue;
                    }
                    self.push(link_abs.clone(), EffectKind::Create, Final::Entry, cmd);
                }
                let points_to = if symbolic {
                    let parent = link_abs.parent().map(Path::to_path_buf).unwrap_or_default();
                    Some(parent.join(target))
                } else {
                    let source = absolute(cwd.as_deref(), target);
                    if let Some(source) = &source {
                        self.push(source.clone(), EffectKind::Alias, Final::Follow, cmd);
                    }
                    source
                };
                // An absolute link path is pinned whatever the cwd (Grok M3).
                let pinned =
                    Path::new(&link_text).is_absolute() || matches!(st.cwds.as_slice(), [Some(_)]);
                if let (Some(points_to), true) = (points_to, pinned) {
                    st.links
                        .push((fuigo_paths::normalize_lexically(&link_abs), points_to));
                }
            }
        }
    }

    /// `tar -x`: only members named on the command line, at `-C DIR/member`; anything else gives no effect.
    fn tar(&mut self, args: &[String], cmd: &Cmd<'_>) {
        let mut words = args.to_vec();
        // Old-style first word (`tar xzf a.tgz`) is a short-option cluster.
        if words.first().is_some_and(|w| !w.starts_with('-')) {
            words[0] = format!("-{}", words[0]);
        }
        let a = Args::parse(
            &words,
            "fCTXbNKgV",
            &["file", "directory", "files-from", "exclude-from"],
        );
        if !(a.has('x') || a.has_long("extract") || a.has_long("get")) {
            return;
        }
        let dir = a
            .value('C')
            .or_else(|| a.long_value("directory"))
            .unwrap_or_else(|| ".".to_owned());
        for i in a.operands {
            let member = join_text(&dir, &words[i]);
            self.emit(cmd, &member, false, EffectKind::Overwrite, Final::Follow);
        }
    }

    /// A destination operand: an existing directory (followed, not `-T`) is written at `DIR/basename(src)`.
    fn emit_dest(
        &mut self,
        cmd: &Cmd<'_>,
        dest: &str,
        sources: &[&str],
        no_target_dir: bool,
        kind: EffectKind,
        fin: Final,
    ) {
        if dest == UNKNOWN {
            return;
        }
        for cwd in cmd.cwds.iter() {
            let Some(abs) = absolute(cwd.as_deref(), dest) else {
                continue;
            };
            if !no_target_dir && std::fs::metadata(&abs).is_ok_and(|m| m.is_dir()) {
                for source in sources {
                    if *source != UNKNOWN {
                        self.push(abs.join(basename(source)), kind, fin, cmd);
                    }
                }
            } else {
                self.push(abs, kind, fin, cmd);
            }
        }
    }

    /// One operand: an unquoted glob is judged at its longest literal parent directory, following it.
    fn emit(&mut self, cmd: &Cmd<'_>, text: &str, glob: bool, kind: EffectKind, fin: Final) {
        if text == UNKNOWN || text.contains('\0') || text.is_empty() {
            return;
        }
        let (text, fin) = if glob {
            let literal = &text[..text.find(['*', '?', '[']).unwrap_or(text.len())];
            let parent = match literal.rfind('/') {
                Some(0) => "/",
                Some(at) => &literal[..at],
                None => ".",
            };
            (parent.to_owned(), Final::Follow)
        } else if text.ends_with('/') || text.ends_with("/.") {
            // `rm -rf link/` acts on what the link points to (Fable r3 H2).
            (text.to_owned(), Final::Follow)
        } else {
            (text.to_owned(), fin)
        };
        let from = self.out.len();
        for cwd in cmd.cwds.iter() {
            if let Some(abs) = absolute(cwd.as_deref(), &text) {
                self.push(abs, kind, fin, cmd);
            }
        }
        if glob {
            self.widen_from(from);
        }
    }

    fn push(&mut self, path: PathBuf, kind: EffectKind, fin: Final, cmd: &Cmd<'_>) {
        self.out.push(S1Effect {
            path,
            kind,
            fin,
            segment: cmd.segment.to_owned(),
            links: cmd.links.to_vec(),
            wide: false,
        });
    }

    fn widen_from(&mut self, from: usize) {
        for effect in &mut self.out[from..] {
            effect.wide = true;
        }
    }
}

#[derive(Clone, Copy)]
struct Cmd<'a> {
    cwds: &'a [Option<PathBuf>],
    segment: &'a str,
    links: &'a [(PathBuf, PathBuf)],
}

impl Cmd<'_> {
    fn owned(&self) -> OwnedCmd {
        OwnedCmd {
            cwds: self.cwds.to_vec(),
            segment: self.segment.to_owned(),
            links: self.links.to_vec(),
        }
    }
}

struct OwnedCmd {
    cwds: Vec<Option<PathBuf>>,
    segment: String,
    links: Vec<(PathBuf, PathBuf)>,
}

impl OwnedCmd {
    fn borrow(&self) -> Cmd<'_> {
        Cmd {
            cwds: &self.cwds,
            segment: &self.segment,
            links: &self.links,
        }
    }
}

fn has_or(list: Node<'_>) -> bool {
    (0..list.child_count())
        .filter_map(|i| list.child(i))
        .any(|c| c.kind() == "||")
}

/// The elements of a pure `&&` chain, nested lists (tree-sitter nests them left-first) flattened.
fn and_chain(list: Node<'_>) -> Vec<Node<'_>> {
    let mut parts = Vec::new();
    for child in named_children(list) {
        if child.kind() == "list" && !has_or(child) {
            parts.extend(and_chain(child));
        } else {
            parts.push(child);
        }
    }
    parts
}

fn named_children<'t>(node: Node<'t>) -> impl Iterator<Item = Node<'t>> {
    (0..node.named_child_count()).filter_map(move |i| node.named_child(i))
}

fn push_words(words: &mut Vec<Word>, decoded: Option<Vec<(String, bool)>>) {
    match decoded {
        Some(list) => words.extend(list.into_iter().map(Some)),
        None => words.push(None),
    }
}

fn assign(node: Node<'_>, src: &str, st: &mut St) {
    let Some(name) = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(src.as_bytes()).ok())
    else {
        return;
    };
    let value = match node.child_by_field_name("value") {
        None => Some(String::new()),
        Some(value) => match decode_node(value, src, st).as_deref() {
            Some([(word, false)]) => Some(word.clone()),
            _ => None,
        },
    };
    match value {
        Some(value) => st.vars.insert(name.to_owned(), value),
        None => st.vars.remove(name),
    };
}

/// `cd`/`pushd` with a same-line assignment substituted into the operand (Fable r3 H1, Astra, Grok r2 #1).
fn change_dir(inner: &[String], st: &mut St) {
    let operands: Vec<&String> = inner[1..]
        .iter()
        .filter(|w| !(w.starts_with('-') && w.len() > 1))
        .collect();
    let target = match operands.as_slice() {
        [] => st.home.clone().map(|h| h.to_string_lossy().into_owned()),
        [one] if *one != "-" && one.as_str() != UNKNOWN => Some((*one).clone()),
        _ => None,
    };
    // The `cd` may fail (a missing directory) and the script go on in the old cwd (Astra H1).
    st.fallback = Some(st.cwds.clone());
    st.cwds = match target {
        Some(target) => st
            .cwds
            .iter()
            .map(|cwd| absolute(cwd.as_deref(), &target))
            .collect(),
        None => vec![None],
    };
    st.cwds.dedup();
}

/// The directories the wrappers in front of a command move it to, in order (`env -C DIR`, `sudo -D DIR`); `None` when a
/// wrapper moves it somewhere the guard cannot read (`sudo -i`/`-R`/`--login`, `chroot`) or no directory is found.
fn moved_dirs(prefix: &[String]) -> Option<Vec<String>> {
    const SUDO_LONG_VALUE: &[&str] = &[
        "close-from",
        "chdir",
        "group",
        "host",
        "prompt",
        "role",
        "type",
        "command-timeout",
        "other-user",
        "user",
    ];
    let mut dirs = Vec::new();
    let mut i = 0;
    while let Some(word) = prefix.get(i) {
        i += 1;
        match shell_program_name(word).to_ascii_lowercase().as_str() {
            "env" => dirs.extend(
                crate::permission::bash_command_splitting::env_chdir(&prefix[i - 1..])
                    .map(str::to_owned),
            ),
            "chroot" => return None,
            "sudo" => {
                while let Some(w) = prefix.get(i).filter(|w| w.starts_with('-') && *w != "--") {
                    if let Some(long) = w.strip_prefix("--") {
                        let (name, value) = long
                            .split_once('=')
                            .map_or((long, None), |(n, v)| (n, Some(v.to_owned())));
                        if matches!(name, "login" | "chroot") {
                            return None;
                        }
                        if SUDO_LONG_VALUE.contains(&name) && value.is_none() {
                            i += 1;
                        }
                        if name == "chdir" {
                            dirs.push(value.or_else(|| prefix.get(i).cloned())?);
                        }
                    } else {
                        for (k, c) in w.char_indices().skip(1) {
                            if matches!(c, 'i' | 'R') {
                                return None;
                            }
                            if "CDghprTtUu".contains(c) {
                                let rest = &w[k + 1..];
                                let value = if rest.is_empty() {
                                    i += 1;
                                    prefix.get(i).cloned()?
                                } else {
                                    rest.to_owned()
                                };
                                if c == 'D' {
                                    dirs.push(value);
                                }
                                break;
                            }
                        }
                    }
                    i += 1;
                }
            }
            _ => {}
        }
    }
    (!dirs.is_empty()).then_some(dirs)
}

fn absolute(cwd: Option<&Path>, text: &str) -> Option<PathBuf> {
    let path = Path::new(text);
    if path.is_absolute() {
        Some(path.to_path_buf())
    } else {
        cwd.map(|cwd| cwd.join(path))
    }
}

fn basename(text: &str) -> &str {
    let trimmed = text.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

fn join_text(dir: &str, name: &str) -> String {
    if Path::new(name).is_absolute() {
        name.to_owned()
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

fn remote_spec(word: &str) -> bool {
    word.split('/')
        .next()
        .is_some_and(|head| head.contains(':'))
}

fn quoted_heredoc_body(statement: Node<'_>, src: &str) -> Option<String> {
    let redirect = named_children(statement).find(|c| c.kind() == "heredoc_redirect")?;
    let start = named_children(redirect).find(|c| c.kind() == "heredoc_start")?;
    let delimiter = start.utf8_text(src.as_bytes()).ok()?;
    if !delimiter.contains(['\'', '"', '\\']) {
        return None;
    }
    let body = named_children(redirect)
        .find(|c| c.kind() == "heredoc_body")
        .or_else(|| named_children(statement).find(|c| c.kind() == "heredoc_body"))?;
    body.utf8_text(src.as_bytes()).ok().map(str::to_owned)
}

/// A GNU-style argv split into flags, option values and operand indexes.
struct Args {
    operands: Vec<usize>,
    short: Vec<(char, Option<String>)>,
    long: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(args: &[String], short_value: &str, long_value: &[&str]) -> Self {
        let mut out = Args {
            operands: Vec::new(),
            short: Vec::new(),
            long: Vec::new(),
        };
        let mut i = 0;
        let mut options_done = false;
        while let Some(word) = args.get(i) {
            i += 1;
            if options_done || word == "-" || !word.starts_with('-') {
                out.operands.push(i - 1);
                continue;
            }
            if word == "--" {
                options_done = true;
                continue;
            }
            if let Some(long) = word.strip_prefix("--") {
                let (name, value) = match long.split_once('=') {
                    Some((name, value)) => (name.to_owned(), Some(value.to_owned())),
                    None if long_value.contains(&long) => {
                        i += 1;
                        (long.to_owned(), args.get(i - 1).cloned())
                    }
                    None => (long.to_owned(), None),
                };
                out.long.push((name, value));
                continue;
            }
            let cluster: Vec<char> = word[1..].chars().collect();
            for (at, option) in cluster.iter().enumerate() {
                if short_value.contains(*option) {
                    let rest: String = cluster[at + 1..].iter().collect();
                    let value = if rest.is_empty() {
                        i += 1;
                        args.get(i - 1).cloned()
                    } else {
                        Some(rest)
                    };
                    out.short.push((*option, value));
                    break;
                }
                out.short.push((*option, None));
            }
        }
        out
    }
    fn has(&self, option: char) -> bool {
        self.short.iter().any(|(o, _)| *o == option)
    }
    fn has_long(&self, name: &str) -> bool {
        self.long.iter().any(|(n, _)| n == name)
    }
    fn has_long_prefix(&self, prefix: &str) -> bool {
        self.long.iter().any(|(n, _)| n.starts_with(prefix))
    }
    fn value(&self, option: char) -> Option<String> {
        self.short
            .iter()
            .rev()
            .find(|(o, _)| *o == option)
            .and_then(|(_, v)| v.clone())
    }
    fn long_value(&self, name: &str) -> Option<String> {
        self.long
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.clone())
    }
}

/// Decode one word node with the shared shell-word decoder, after substituting `HOME` and same-line assignments.
fn decode_node(node: Node<'_>, src: &str, st: &St) -> Option<Vec<(String, bool)>> {
    decode_word(
        node.utf8_text(src.as_bytes()).ok()?,
        &st.vars,
        st.home.as_deref(),
    )
}

pub(crate) fn decode_word(
    raw: &str,
    vars: &HashMap<String, String>,
    home: Option<&Path>,
) -> Option<Vec<(String, bool)>> {
    let substituted = substitute(raw, vars, home)?;
    let words = crate::permission::shell_words::normalise_word_marking_globs(&substituted).ok()?;
    Some(
        words
            .into_iter()
            .map(|w| {
                let glob = w.glob != crate::permission::shell_words::GlobMark::Literal;
                (w.text, glob)
            })
            .collect(),
    )
}

fn single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Replace a leading unquoted `~` and every `$NAME`/`${NAME}` whose value is known with a quoted literal. An unknown
/// variable or any other expansion makes the word unpinned (`None`); an unquoted value that would split or glob too.
fn substitute(raw: &str, vars: &HashMap<String, String>, home: Option<&Path>) -> Option<String> {
    if !raw.contains(['$', '~']) {
        return Some(raw.to_owned());
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    let (mut single, mut double) = (false, false);
    if chars.first() == Some(&'~') && matches!(chars.get(1), None | Some('/')) {
        out.push_str(&single_quoted(&home?.to_string_lossy()));
        i = 1;
    }
    while let Some(&ch) = chars.get(i) {
        i += 1;
        if single {
            out.push(ch);
            single = ch != '\'';
            continue;
        }
        match ch {
            '\\' => {
                out.push(ch);
                if let Some(&next) = chars.get(i) {
                    out.push(next);
                    i += 1;
                }
            }
            '\'' if !double => {
                single = true;
                out.push(ch);
            }
            '"' => {
                double = !double;
                out.push(ch);
            }
            '$' => {
                let braced = chars.get(i) == Some(&'{');
                let start = i + usize::from(braced);
                let mut end = start;
                while chars
                    .get(end)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    end += 1;
                }
                if end == start
                    || chars[start].is_ascii_digit()
                    || (braced && chars.get(end) != Some(&'}'))
                {
                    return None;
                }
                let name: String = chars[start..end].iter().collect();
                let value = vars.get(&name)?;
                i = end + usize::from(braced);
                if double {
                    for c in value.chars() {
                        if matches!(c, '\\' | '"' | '$' | '`') {
                            out.push('\\');
                        }
                        out.push(c);
                    }
                } else {
                    if value.is_empty()
                        || value.contains(|c: char| c.is_whitespace() || "*?[".contains(c))
                    {
                        return None;
                    }
                    out.push_str(&single_quoted(value));
                }
            }
            _ => out.push(ch),
        }
    }
    Some(out)
}

// ───────────────────────────── resolution ─────────────────────────────

/// A target as the kernel reaches it: every component resolved before a following `..` applies, links made earlier
/// on the same line applied, and the existing part canonicalised (so case follows the disk).
#[derive(Debug, Clone)]
pub(crate) struct Reached {
    pub(crate) path: PathBuf,
    pub(crate) exists: bool,
    /// A component could not be read (permission, read-link error, a link loop): the path is not proven anywhere, so
    /// it never counts as inside a root (Astra H7).
    pub(crate) indeterminate: bool,
}

pub(crate) fn reach(path: &Path, follow_final: bool, links: &[(PathBuf, PathBuf)]) -> Reached {
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    push_components(&mut rest, path);
    let mut cur = PathBuf::from("/");
    let mut hops = 0;
    let mut missing = false;
    let mut indeterminate = false;
    while let Some(part) = rest.pop() {
        if part == "." {
            continue;
        }
        if part == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(&part);
        if missing || (rest.is_empty() && !follow_final) {
            cur = next;
            continue;
        }
        let virtual_target = links
            .iter()
            .rev()
            .find(|(link, _)| *link == next)
            .map(|(_, to)| to.clone());
        let target = match virtual_target {
            Some(to) => Some(to),
            None => match std::fs::symlink_metadata(&next) {
                Ok(meta) if meta.file_type().is_symlink() => match std::fs::read_link(&next) {
                    Ok(to) => Some(cur.join(to)),
                    Err(_) => {
                        indeterminate = true;
                        None
                    }
                },
                Ok(_) => None,
                Err(e) => {
                    missing = true;
                    indeterminate |= e.kind() != std::io::ErrorKind::NotFound;
                    None
                }
            },
        };
        match target {
            Some(to) => {
                hops += 1;
                if hops > MAX_LINK_HOPS {
                    return Reached {
                        path: next,
                        exists: true,
                        indeterminate: true,
                    };
                }
                push_components(&mut rest, &to);
                cur = PathBuf::from("/");
            }
            None => cur = next,
        }
    }
    // Missing and indeterminate parts stay lexical; an unreadable component counts as existing (fail safe).
    let exists = if indeterminate {
        true
    } else if missing {
        false
    } else {
        // Only a genuine NotFound is absent; any other error on the final component counts as existing (Astra H5).
        let meta = if follow_final {
            std::fs::metadata(&cur)
        } else {
            std::fs::symlink_metadata(&cur)
        };
        meta.map_or_else(
            |e| {
                !matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                )
            },
            |_| true,
        )
    };
    Reached {
        path: canonical_prefix(&cur, follow_final),
        exists,
        indeterminate,
    }
}

fn push_components(rest: &mut Vec<std::ffi::OsString>, path: &Path) {
    let parts: Vec<std::ffi::OsString> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some("..".into()),
            _ => None,
        })
        .collect();
    rest.extend(parts.into_iter().rev());
}

/// `path` with its deepest existing ancestor canonicalised (the leaf itself only when following it).
fn canonical_prefix(path: &Path, follow_final: bool) -> PathBuf {
    let (base, leaf) = match (follow_final, path.parent(), path.file_name()) {
        (false, Some(parent), Some(name)) => (parent, Some(name)),
        _ => (path, None),
    };
    let mut tail = Vec::new();
    let mut probe = base;
    let canonical = loop {
        if let Ok(c) = dunce::canonicalize(probe) {
            break c;
        }
        match (probe.parent(), probe.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                probe = parent;
            }
            _ => break probe.to_path_buf(),
        }
    };
    let mut out = canonical;
    for name in tail.into_iter().rev() {
        out.push(name);
    }
    if let Some(leaf) = leaf {
        out.push(leaf);
    }
    out
}

#[cfg(unix)]
fn hard_linked_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.nlink() > 1)
}

#[cfg(not(unix))]
fn hard_linked_file(_path: &Path) -> bool {
    false
}

// ───────────────────────────── the session state and the check ─────────────────────────────

/// What a session's guard is judged against: the roots inside which nothing asks, and the user's homes.
#[derive(Debug, Clone)]
pub struct GuardEnv {
    roots: Vec<PathBuf>,
    session_root: PathBuf,
    home: Option<PathBuf>,
    fuigo_home: Option<PathBuf>,
    /// Each authority root's resolved form and its spelling (`~/.claude`, `$FUIGO_HOME`), so a write through the
    /// physical path of a symlinked root still matches the authority files (Astra H5).
    aliases: Vec<(PathBuf, PathBuf)>,
}

/// The authority roots whose resolved form differs from their spelling.
fn authority_aliases(home: Option<&Path>, fuigo_home: Option<&Path>) -> Vec<(PathBuf, PathBuf)> {
    home.map(|h| h.join(".claude"))
        .into_iter()
        .chain(fuigo_home.map(Path::to_path_buf))
        .filter_map(|root| {
            dunce::canonicalize(&root)
                .ok()
                .filter(|c| *c != root)
                .map(|c| (c, root))
        })
        .collect()
}

impl GuardEnv {
    /// The production roots, computed once at session start: the session root, its git worktree root (only an
    /// ancestor, never `/`, a first-level directory or `$HOME`), `$FUIGO_HOME`, the temp dirs, `/tmp` and `/var/tmp`.
    pub fn for_session(session_root: &Path) -> Self {
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from);
        let canon = |p: &Path| dunce::canonicalize(p).ok();
        let session = canon(session_root).unwrap_or_else(|| session_root.to_path_buf());
        let home_canon = home.as_deref().and_then(canon);
        let broad = |p: &Path| p.components().count() <= 2 || home_canon.as_deref() == Some(p);
        let mut roots = vec![session.clone()];
        if let Some(git) = session
            .ancestors()
            .find(|dir| dir.join(".git").exists())
            .filter(|git| !broad(git))
        {
            roots.push(git.to_path_buf());
        }
        let fuigo_home = fuigo_config::user_fuigo_home();
        let mut candidates: Vec<PathBuf> = fuigo_home.iter().cloned().collect();
        candidates.push(std::env::temp_dir());
        candidates.extend(std::env::var_os("TMPDIR").map(PathBuf::from));
        for dir in candidates.iter().filter_map(|d| canon(d)) {
            if !broad(&dir) && !roots.contains(&dir) {
                roots.push(dir);
            }
        }
        for dir in ["/tmp", "/var/tmp"]
            .iter()
            .filter_map(|d| canon(Path::new(d)))
        {
            if !roots.contains(&dir) {
                roots.push(dir);
            }
        }
        Self {
            roots,
            session_root: session,
            aliases: authority_aliases(home.as_deref(), fuigo_home.as_deref()),
            home,
            fuigo_home,
        }
    }

    /// Injected roots (tests).
    pub fn with_roots(
        roots: Vec<PathBuf>,
        home: Option<PathBuf>,
        fuigo_home: Option<PathBuf>,
    ) -> Self {
        let roots: Vec<PathBuf> = roots
            .into_iter()
            .map(|r| dunce::canonicalize(&r).unwrap_or(r))
            .collect();
        Self {
            session_root: roots.first().cloned().unwrap_or_else(|| PathBuf::from("/")),
            roots,
            aliases: authority_aliases(home.as_deref(), fuigo_home.as_deref()),
            home,
            fuigo_home,
        }
    }

    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }

    fn inside(&self, reached: &Path) -> bool {
        self.roots.iter().any(|root| reached.starts_with(root))
    }

    fn broad(&self, path: &Path) -> bool {
        path.components().count() <= 2 || self.home.as_deref() == Some(path)
    }

    /// A user-tier file Fuigo reads as the user's authority, by spelling (r3 §1): under `~/.claude` or `$FUIGO_HOME`,
    /// the config and settings files, the hook roots, the sandbox and MCP config, the per-session grant stores, and the
    /// folder-trust inputs. Any write to one counts. Everything else under `$FUIGO_HOME` (sessions, `/goal` plans,
    /// memory, worktrees) is inside the workspace like any root (Fable H3).
    fn authority_path(&self, path: &Path) -> bool {
        self.authority_spelled(path)
            || self.aliases.iter().any(|(resolved, spelled)| {
                path.strip_prefix(resolved)
                    .is_ok_and(|rest| self.authority_spelled(&spelled.join(rest)))
            })
    }

    fn authority_spelled(&self, path: &Path) -> bool {
        use crate::permission::ProtectedEditReason as R;
        let in_claude = self
            .home
            .as_ref()
            .is_some_and(|home| path.starts_with(home.join(".claude")));
        let in_fuigo = self
            .fuigo_home
            .as_ref()
            .is_some_and(|f| path.starts_with(f) && !path.starts_with(f.join("worktrees")));
        (in_claude || in_fuigo)
            && (matches!(
                protected_edit_reason(path),
                Some(
                    R::FuigoConfig
                        | R::ClaudeSettings
                        | R::HookRoot
                        | R::FuigoSandbox
                        | R::McpConfig
                )
            ) || crate::folder_trust::trust_input_paths()
                .iter()
                .any(|f| f == path))
    }

    /// The same, by file identity (Astra r3 N2): an existing file with other names that IS an authority file.
    fn authority_identity(&self, reached: &Path) -> bool {
        if !hard_linked_file(reached) {
            return false;
        }
        let Ok(target) = same_file::Handle::from_path(reached) else {
            return true;
        };
        let mut files = crate::folder_trust::trust_input_paths();
        if let Some(home) = &self.home {
            files.push(home.join(".claude").join("settings.json"));
            files.push(home.join(".claude").join("settings.local.json"));
        }
        if let Some(fuigo) = &self.fuigo_home {
            files.push(fuigo.join(fuigo_config::USER_CONFIG_FILENAME));
        }
        files
            .iter()
            .any(|f| same_file::Handle::from_path(f).ok().as_ref() == Some(&target))
    }
}

#[derive(Debug, Clone)]
struct Token {
    lexical: PathBuf,
    /// As typed (joined to its base, `..` kept): resolved in kernel order for the containment check (Astra H7).
    spelled: PathBuf,
    broad: bool,
}

#[derive(Debug, Clone)]
struct Created {
    lexical: PathBuf,
    reached: PathBuf,
    link: bool,
}

/// A path absent when an allowed request was decided: recorded as created if its resolved form exists afterwards.
#[derive(Debug, Clone, PartialEq)]
struct Pending {
    lexical: PathBuf,
    /// The resolved target that was absent (Fable H2: the record is keyed on what the kernel reaches).
    reached: PathBuf,
    /// Requests seen since; dropped after [`PENDING_TTL`] so a path someone else creates later is not adopted.
    age: u8,
}

const PENDING_TTL: u8 = 16;

/// A remembered approval: the exact resolved path.
#[derive(Debug, Clone, PartialEq)]
struct Approved {
    path: PathBuf,
}

#[derive(Debug, Default)]
struct Inner {
    env: Option<GuardEnv>,
    tokens: Vec<Token>,
    approved: Vec<Approved>,
    created: Vec<Created>,
    pending: Vec<Pending>,
    rules: Option<Vec<PermissionRule>>,
    /// The ACP host declared `fuigo/permissionPrompts` at initialize: it answers `session/request_permission`.
    client_prompts: bool,
}

/// The session's S1 state, shared by every clone of its permission handle (subagents included), in memory only.
#[derive(Debug, Clone, Default)]
pub struct OutsideGuard(Arc<Mutex<Inner>>);

/// What the guard found for one request.
#[derive(Debug, Clone, Default)]
pub struct OutsideVerdict {
    pub change: Option<OutsideChange>,
    approve: Vec<Approved>,
    pending: Vec<Pending>,
}

/// The paths a request would change outside the workspace without an exemption, for the prompt note and deny text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutsideChange {
    pub paths: Vec<String>,
    pub root: String,
    /// The host can show the prompt even when its client type is not a recognised Fuigo client.
    pub client_prompts: bool,
    /// The command did not parse, so what it changes is not known.
    pub unparsed: bool,
}

impl OutsideChange {
    fn named(&self) -> String {
        let first = self.paths.first().map(String::as_str).unwrap_or_default();
        match self.paths.len() {
            0 | 1 => format!("`{first}`"),
            n => format!("`{first}` and {} more", n - 1),
        }
    }

    pub fn prompt_note(&self) -> String {
        if self.paths.is_empty() && self.unparsed {
            return "Fuigo could not parse this command, so it cannot tell whether it deletes or changes files outside \
                    the workspace. Allow it only if you want this."
                .to_owned();
        }
        format!(
            "This would delete or change {}, which is outside the workspace and was not named by you. Allow it only \
             if you want this.",
            self.named()
        )
    }

    pub fn deny_text(&self) -> String {
        if self.paths.is_empty() && self.unparsed {
            return format!(
                "Not run: this command could not be parsed, so Fuigo cannot tell whether it deletes or changes files \
                 outside the workspace ({}). Rewrite it in plain shell syntax, or tell the user which command you \
                 wanted to run and why.",
                self.root
            );
        }
        format!(
            "Not run: this command would delete or change {}, outside the workspace ({}). The user did not name that \
             path. Do not try another way to do this. Finish the rest of the task, then tell the user which command \
             you wanted to run and why. They can name the path in their prompt (again, if this session was resumed), \
             pre-allow it with `--allow`, or run it themselves.",
            self.named(),
            self.root
        )
    }
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl OutsideGuard {
    /// Compute the roots on the session's first use; later calls keep them.
    pub fn ensure_env(&self, session_root: &Path) {
        let mut inner = lock(&self.0);
        if inner.env.is_none() {
            inner.env = Some(GuardEnv::for_session(session_root));
        }
    }

    pub fn install_env(&self, env: GuardEnv) {
        lock(&self.0).env = Some(env);
    }

    pub fn home(&self) -> Option<PathBuf> {
        lock(&self.0).env.as_ref().and_then(|e| e.home.clone())
    }

    pub fn rules_sealed(&self) -> bool {
        lock(&self.0).rules.is_some()
    }

    /// The CLI and user-tier allow rules loaded at session start; a rule written later never exempts (Grok r3 H3).
    /// The host answers permission prompts (`initialize` `_meta."fuigo/permissionPrompts": true`); never cleared.
    pub fn set_client_prompts(&self) {
        lock(&self.0).client_prompts = true;
    }

    pub fn set_rules_once(&self, rules: Vec<PermissionRule>) {
        let mut inner = lock(&self.0);
        if inner.rules.is_none() {
            inner.rules = Some(
                rules
                    .into_iter()
                    .filter(|r| r.action == RuleAction::Allow && r.pattern.is_some())
                    .collect(),
            );
        }
    }

    /// Paths the user typed in a `PromptOrigin::User` prompt: words containing `/` or starting with `~` or `$HOME`
    /// (quoting only keeps spaces inside such a path). `~` and `$HOME` expand as the shell does; a relative word is
    /// absolute against the session root and the shell's cwd.
    pub fn note_user_text(&self, text: &str, session_root: &Path, exec_dir: Option<&Path>) {
        self.ensure_env(session_root);
        let mut inner = lock(&self.0);
        let Some(env) = inner.env.clone() else { return };
        for word in user_words(text) {
            let expanded = match expand_home(&word, env.home.as_deref()) {
                Some(path) => path,
                None => continue,
            };
            let bases: Vec<&Path> = if expanded.is_absolute() {
                vec![Path::new("/")]
            } else {
                std::iter::once(session_root).chain(exec_dir).collect()
            };
            for base in bases {
                let spelled = base.join(&expanded);
                let lexical = fuigo_paths::normalize_lexically(&spelled);
                // A typed directory that resolves to `/`, a first-level directory or `$HOME` covers only itself (Grok M4).
                let broad = env.broad(&lexical) || env.broad(&reach(&spelled, true, &[]).path);
                if !inner.tokens.iter().any(|t| t.spelled == spelled) {
                    inner.tokens.push(Token {
                        lexical,
                        spelled,
                        broad,
                    });
                }
            }
        }
    }

    /// Judge a request's effects. `bash` selects the rule kind a pre-allow must be (`Bash(...)` or `Edit(...)`).
    pub(crate) fn evaluate(&self, effects: &[S1Effect], bash: bool) -> OutsideVerdict {
        let (env, tokens, approved, created, rules) = {
            let mut inner = lock(&self.0);
            promote_pending(&mut inner);
            let Some(env) = inner.env.clone() else {
                return OutsideVerdict::default();
            };
            (
                env,
                inner.tokens.clone(),
                inner.approved.clone(),
                inner.created.clone(),
                inner.rules.clone().unwrap_or_default(),
            )
        };
        let mut verdict = OutsideVerdict::default();
        let mut shown = Vec::new();
        let mut unparsed = false;
        for effect in effects {
            if effect.kind == EffectKind::Unparsed {
                unparsed = true;
                continue;
            }
            let lexical = fuigo_paths::normalize_lexically(&effect.path);
            if is_sink(&lexical) {
                continue;
            }
            let modes: &[bool] = match effect.fin {
                Final::Entry => &[false],
                Final::Follow => &[true],
                Final::Both => &[false, true],
            };
            for &follow in modes {
                let reached = reach(&effect.path, follow, &effect.links);
                let authority = env.authority_path(&lexical)
                    || env.authority_path(&reached.path)
                    || (reached.exists && env.authority_identity(&reached.path));
                // Only an absent path outside the roots can become an agent-created file (Fable M7).
                if !reached.exists
                    && !env.inside(&reached.path)
                    && matches!(
                        effect.kind,
                        EffectKind::Create | EffectKind::Overwrite | EffectKind::Append
                    )
                {
                    let pending = Pending {
                        lexical: lexical.clone(),
                        reached: reached.path.clone(),
                        age: 0,
                    };
                    if !verdict.pending.contains(&pending) {
                        verdict.pending.push(pending);
                    }
                }
                let inside = !reached.indeterminate && env.inside(&reached.path);
                let destructive = authority
                    || (reached.exists
                        && matches!(effect.kind, EffectKind::Remove | EffectKind::Overwrite)
                        && !inside);
                if !destructive {
                    continue;
                }
                // An approval covers its exact resolved path only, a workspace link's directory included (Fable M4).
                let approved_here = approved.iter().any(|a| reached.path == a.path);
                let exempt = typed(&tokens, &lexical, &reached.path, follow)
                    || approved_here
                    || (!authority
                        && (created_by_agent(&created, &lexical, &reached.path, follow)
                            || pre_allowed(&rules, &env, effect, bash, &lexical, &reached.path)));
                if exempt {
                    continue;
                }
                // `$HOME`, `/`, a first-level directory and anything that stood for what lies under it (a glob's
                // parent, a `find` start) are never remembered.
                if !effect.wide && !env.broad(&reached.path) {
                    let exact = Approved {
                        path: reached.path.clone(),
                    };
                    if !verdict.approve.contains(&exact) {
                        verdict.approve.push(exact);
                    }
                }
                let display = lexical.to_string_lossy().into_owned();
                if !shown.contains(&display) {
                    shown.push(display);
                }
            }
        }
        // A path that was an S1 hit is never recorded as created.
        if !shown.is_empty() || unparsed {
            verdict
                .pending
                .retain(|p| !shown.iter().any(|s| Path::new(s) == p.lexical.as_path()));
            verdict.change = Some(OutsideChange {
                paths: shown,
                root: env.session_root.to_string_lossy().into_owned(),
                client_prompts: lock(&self.0).client_prompts,
                unparsed,
            });
        }
        verdict
    }

    /// After the decision: an allowed request's S1 hits were approved by the user (remembered by resolved path for
    /// the session, Fable r3 H5), and the paths it may create are checked for existence at the next request.
    pub fn after_decision(&self, verdict: &OutsideVerdict, allowed: bool) {
        if !allowed {
            return;
        }
        let mut inner = lock(&self.0);
        if verdict.change.is_some() {
            for approval in &verdict.approve {
                if !inner.approved.contains(approval) {
                    inner.approved.push(approval.clone());
                }
            }
        }
        for pending in &verdict.pending {
            if !inner.pending.contains(pending) && inner.pending.len() < 4096 {
                inner.pending.push(pending.clone());
            }
        }
    }
}

/// A resolved path absent when an allowed request was decided that exists now was created by it (Astra r3: what
/// happened, not the command's syntax). The record is the resolved path, so a `..` across a link cannot make an
/// existing file look created (Fable H2). A hard-linked file is never recorded (Fable r3 M9).
fn promote_pending(inner: &mut Inner) {
    let pending = std::mem::take(&mut inner.pending);
    for mut p in pending {
        match std::fs::symlink_metadata(&p.reached) {
            Ok(meta) => {
                let link = meta.file_type().is_symlink();
                if !link && hard_linked_file(&p.reached) {
                    continue;
                }
                if inner.created.len() < 4096 {
                    inner.created.push(Created {
                        lexical: p.lexical,
                        reached: p.reached,
                        link,
                    });
                }
            }
            Err(_) if p.age < PENDING_TTL => {
                p.age += 1;
                inner.pending.push(p);
            }
            Err(_) => {}
        }
    }
}

fn is_sink(path: &Path) -> bool {
    path.starts_with("/dev")
        || path.starts_with("/proc/self/fd")
        || is_safe_write_sink(&path.to_string_lossy())
}

/// Sean 11-21 (1): the lexical match on the typed spelling (`.`/`..` collapsed), and the resolved target must still be
/// inside the resolved typed path, so no link below a typed folder (Fable r3 H4) and no `..` across a link (Astra r3
/// N1) borrows its authority.
fn typed(tokens: &[Token], lexical: &Path, reached: &Path, follow: bool) -> bool {
    tokens.iter().any(|t| {
        let exact = lexical == t.lexical;
        if !(exact || (!t.broad && lexical.starts_with(&t.lexical))) {
            return false;
        }
        let typed_reached = reach(&t.spelled, !exact || follow, &[]).path;
        reached == typed_reached || (!t.broad && reached.starts_with(&typed_reached))
    })
}

/// Both the spelled and the resolved path are equal to or under a recorded one; a recorded link covers only removing
/// the link itself; a file with other names is never covered.
fn created_by_agent(created: &[Created], lexical: &Path, reached: &Path, follow: bool) -> bool {
    !hard_linked_file(reached)
        && created.iter().any(|c| {
            if c.link {
                !follow && lexical == c.lexical
            } else {
                lexical.starts_with(&c.lexical) && reached.starts_with(&c.reached)
            }
        })
}

/// A CLI or user-tier allow rule loaded at session start that matches the segment performing the effect and spells
/// the target (lexical or resolved) or a non-broad parent of it literally (Fable r3 M8).
fn pre_allowed(
    rules: &[PermissionRule],
    env: &GuardEnv,
    effect: &S1Effect,
    bash: bool,
    lexical: &Path,
    reached: &Path,
) -> bool {
    rules.iter().any(|rule| {
        let Some(pattern) = rule.pattern.as_deref() else {
            return false;
        };
        let kind_ok = match rule.tool {
            ToolFilter::Bash => bash,
            ToolFilter::Edit => !bash,
            ToolFilter::Any => true,
            _ => false,
        };
        if !kind_ok
            || (bash
                && !crate::permission::policy::bash_pattern_matches_command(
                    pattern,
                    &effect.segment,
                ))
        {
            return false;
        }
        let words: Vec<&str> = if bash {
            pattern.split_whitespace().collect()
        } else {
            vec![pattern]
        };
        words.into_iter().any(|word| {
            let word = word.trim_matches(['\'', '"']);
            let (literal, parent_only) = match word.find(['*', '?', '[']) {
                Some(at) => match word[..at].rfind('/') {
                    Some(slash) => (&word[..=slash], true),
                    None => return false,
                },
                None => (word, false),
            };
            let Some(spelled) =
                expand_home(literal, env.home.as_deref()).filter(|p| p.is_absolute())
            else {
                return false;
            };
            let spelled = fuigo_paths::normalize_lexically(&spelled);
            [lexical, reached].iter().any(|target| {
                (!parent_only && *target == spelled)
                    || (!env.broad(&spelled) && target.starts_with(&spelled) && *target != spelled)
            })
        })
    })
}

fn expand_home(word: &str, home: Option<&Path>) -> Option<PathBuf> {
    let rest = if word == "~" || word.starts_with("~/") {
        Some(&word[1..])
    } else if word.starts_with('~') {
        return None;
    } else {
        word.strip_prefix("${HOME}")
            .or_else(|| word.strip_prefix("$HOME"))
    };
    match rest {
        Some(rest) => Some(PathBuf::from(format!(
            "{}{rest}",
            home?.to_string_lossy().trim_end_matches('/')
        ))),
        None if word.contains('$') => None,
        None => Some(PathBuf::from(word)),
    }
}

/// Path-shaped words of a user prompt, with surrounding quotes, backticks and brackets and trailing punctuation
/// stripped (Fable r3 M10, Grok r3 #8). Bare words, quoted or not, are never tokens (Fable r3 H3).
fn user_words(text: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    // A quoted path is one word: its space-separated pieces are not tokens of their own (Astra H6). A quoted span that
    // is not path-shaped (an apostrophe in prose) leaves the text as it was.
    let mut rest = text.to_owned();
    for quote in ['"', '\'', '`'] {
        let spans: Vec<(usize, &str)> = text.match_indices(quote).collect();
        for pair in spans.chunks_exact(2) {
            let (open, close) = (pair[0].0 + 1, pair[1].0);
            let inside = &text[open..close];
            words.push(inside.to_owned());
            let path_shaped = ["/", "~", "$HOME", "${HOME}", "./", "../"]
                .iter()
                .any(|p| inside.trim().starts_with(p));
            if path_shaped && inside.contains(char::is_whitespace) {
                rest.replace_range(open..close, &" ".repeat(close - open));
            }
        }
    }
    words.extend(rest.split_whitespace().map(str::to_owned));
    words
        .into_iter()
        .map(|w| {
            let mut w = w.trim().to_owned();
            for _ in 0..3 {
                w = w
                    .trim_matches(|c| "\"'`()[]{}<>".contains(c))
                    .trim_end_matches(|c| ".,:;!?".contains(c))
                    .to_owned();
            }
            w
        })
        .filter(|w| {
            w.contains('/')
                || w.starts_with('~')
                || w.starts_with("$HOME")
                || w.starts_with("${HOME}")
        })
        .collect()
}

#[cfg(all(test, unix))]
#[path = "outside_change_tests.rs"]
mod outside_change_tests;
