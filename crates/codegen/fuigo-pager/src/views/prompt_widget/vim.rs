//! Vim editing for the agent prompt (`[keys] vim = "all"`).
//!
//! The engine is a small modal layer over [`TextArea`]: Insert mode passes every key through to the normal prompt handling, and Normal mode
//! interprets motions, operators, counts, a single unnamed register and undo/redo.
//! It is only consulted when the prompt-vim flag is on, so with vim off or `nav` the prompt's key handling is untouched.
//!
//! Positions are byte offsets on `char` boundaries, as in [`TextArea`].
//! Lines are logical lines (split on `\n`), not wrapped display rows.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use fuigo_ratatui_textarea::TextArea;

/// Which vim mode the prompt is in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum VimMode {
    /// Typing inserts text; Esc leaves for Normal.
    #[default]
    Insert,
    /// Keys are commands.
    Normal,
}

impl VimMode {
    /// Info-line label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Insert => "INSERT",
            Self::Normal => "NORMAL",
        }
    }
}

/// Result of offering a key to the vim layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VimKey {
    /// The vim layer did not take the key; the caller handles it as it does without vim.
    Pass,
    /// The key was consumed (a command ran, was swallowed, or is waiting for its next key).
    Consumed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Delete,
    Change,
    Yank,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FindKind {
    /// `f`
    Find,
    /// `t`
    Till,
    /// `F`
    FindBack,
    /// `T`
    TillBack,
}

impl FindKind {
    fn reversed(self) -> Self {
        match self {
            Self::Find => Self::FindBack,
            Self::FindBack => Self::Find,
            Self::Till => Self::TillBack,
            Self::TillBack => Self::Till,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Pending {
    #[default]
    None,
    /// After `g`, waiting for the second `g`.
    G,
    /// After `f`/`t`/`F`/`T`, waiting for the target character.
    Find(FindKind),
    /// After `r`, waiting for the replacement character.
    Replace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Motion {
    Left,
    Right,
    Down,
    Up,
    WordFwd,
    WordBack,
    WordEnd,
    LineStart,
    FirstNonBlank,
    LineEnd,
    FileStart,
    FileEnd,
    /// Find a character; the flag marks a `;`/`,` repeat.
    Find(FindKind, char, bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Exclusive,
    Inclusive,
    Linewise,
}

#[derive(Clone, Copy, Debug)]
struct Reach {
    target: usize,
    kind: Kind,
}

/// Modal state for the prompt editor.
#[derive(Debug, Default)]
pub(crate) struct VimState {
    pub(super) mode: VimMode,
    /// Digits typed so far (the count after any operator).
    count: Option<usize>,
    op: Option<Op>,
    /// The count typed before the operator (`2d3w` is 6 words).
    op_count: Option<usize>,
    pending: Pending,
    last_find: Option<(FindKind, char)>,
    reg_text: String,
    reg_linewise: bool,
    /// Column kept across consecutive `j`/`k`.
    want_col: Option<usize>,
    /// An undo group is open (an Insert session, or a command that enters Insert).
    group_open: bool,
}

// ---- text helpers --------------------------------------------------------------------------------------------------

fn line_start(t: &str, pos: usize) -> usize {
    t[..pos].rfind('\n').map_or(0, |i| i + 1)
}

fn line_end(t: &str, pos: usize) -> usize {
    t[pos..].find('\n').map_or(t.len(), |i| pos + i)
}

fn char_len_at(t: &str, pos: usize) -> usize {
    t[pos..].chars().next().map_or(0, char::len_utf8)
}

fn next_pos(t: &str, pos: usize) -> usize {
    pos + char_len_at(t, pos)
}

fn prev_pos(t: &str, pos: usize) -> usize {
    t[..pos].char_indices().next_back().map_or(0, |(i, _)| i)
}

fn col_of(t: &str, pos: usize) -> usize {
    t[line_start(t, pos)..pos].chars().count()
}

fn last_char_pos(t: &str, ls: usize, le: usize) -> usize {
    if le > ls { prev_pos(t, le) } else { ls }
}

/// Byte offset of char column `col` on the line, clamped to the last character.
fn pos_at_col(t: &str, ls: usize, le: usize, col: usize) -> usize {
    let mut p = ls;
    for _ in 0..col {
        let n = next_pos(t, p);
        if n >= le {
            return last_char_pos(t, ls, le);
        }
        p = n;
    }
    p.min(last_char_pos(t, ls, le))
}

/// Normal mode keeps the cursor on a character, never past the end of a non-empty line.
fn clamp_normal(t: &str, pos: usize) -> usize {
    let pos = pos.min(t.len());
    let ls = line_start(t, pos);
    let le = line_end(t, pos);
    if pos == le && le > ls {
        prev_pos(t, le)
    } else {
        pos
    }
}

fn first_nonblank(t: &str, ls: usize, le: usize) -> usize {
    let mut p = ls;
    while p < le && matches!(t.as_bytes()[p], b' ' | b'\t') {
        p += 1;
    }
    if p >= le && le > ls {
        last_char_pos(t, ls, le)
    } else {
        p
    }
}

fn nth_line_start(t: &str, n: usize) -> usize {
    let mut start = 0;
    for _ in 0..n {
        let e = line_end(t, start);
        if e >= t.len() {
            break;
        }
        start = e + 1;
    }
    start
}

/// End of the line `extra` lines below the one containing `pos` (clamped to the last line).
fn line_end_below(t: &str, pos: usize, extra: usize) -> usize {
    let mut le = line_end(t, pos);
    for _ in 0..extra {
        if le >= t.len() {
            break;
        }
        le = line_end(t, le + 1);
    }
    le
}

/// Word class: 0 blank, 1 punctuation, 2 keyword.
fn class(c: char) -> u8 {
    if c.is_whitespace() {
        0
    } else if c.is_alphanumeric() || c == '_' {
        2
    } else {
        1
    }
}

type Chars = Vec<(usize, char)>;

fn word_fwd(cs: &Chars, start: usize) -> usize {
    let n = cs.len();
    let mut i = start;
    if i >= n {
        return n;
    }
    let c = class(cs[i].1);
    if c != 0 {
        while i < n && class(cs[i].1) == c {
            i += 1;
        }
    }
    while i < n {
        let ch = cs[i].1;
        if !ch.is_whitespace() {
            break;
        }
        // An empty line is a word of its own.
        if ch == '\n' && i > start && i > 0 && cs[i - 1].1 == '\n' {
            break;
        }
        i += 1;
    }
    i
}

fn word_back(cs: &Chars, start: usize) -> usize {
    if start == 0 || cs.is_empty() {
        return 0;
    }
    let mut i = start.min(cs.len()) - 1;
    while i > 0 && cs[i].1.is_whitespace() {
        if cs[i].1 == '\n' && cs[i - 1].1 == '\n' {
            return i;
        }
        i -= 1;
    }
    let c = class(cs[i].1);
    while i > 0 && class(cs[i - 1].1) == c {
        i -= 1;
    }
    i
}

fn word_end(cs: &Chars, start: usize) -> usize {
    let n = cs.len();
    if n == 0 {
        return 0;
    }
    let mut i = start + 1;
    while i < n && cs[i].1.is_whitespace() {
        i += 1;
    }
    if i >= n {
        return n - 1;
    }
    let c = class(cs[i].1);
    while i + 1 < n && class(cs[i + 1].1) == c {
        i += 1;
    }
    i
}

fn run_end(cs: &Chars, start: usize) -> usize {
    let c = class(cs[start].1);
    let mut i = start;
    while i + 1 < cs.len() && class(cs[i + 1].1) == c {
        i += 1;
    }
    i
}

/// Resolve a motion from `cur`. `None` means the motion failed (nothing moves, a pending operator is cancelled).
fn reach(
    t: &str,
    cur: usize,
    mk: Motion,
    count: Option<usize>,
    op: Option<Op>,
    want_col: &mut Option<usize>,
) -> Option<Reach> {
    let n = count.unwrap_or(1).max(1);
    let ls = line_start(t, cur);
    let le = line_end(t, cur);
    let excl = |target| Some(Reach { target, kind: Kind::Exclusive });
    let incl = |target| Some(Reach { target, kind: Kind::Inclusive });
    match mk {
        Motion::Left => {
            if cur == ls {
                return None;
            }
            let mut p = cur;
            for _ in 0..n {
                if p == ls {
                    break;
                }
                p = prev_pos(t, p);
            }
            excl(p)
        }
        Motion::Right => {
            // An operator may reach the end of the line; a bare move stops on the last character
            let limit = if op.is_some() { le } else { last_char_pos(t, ls, le) };
            if cur >= limit {
                return None;
            }
            let mut p = cur;
            for _ in 0..n {
                if p >= limit {
                    break;
                }
                p = next_pos(t, p);
            }
            excl(p)
        }
        Motion::Down | Motion::Up => {
            let col = want_col.unwrap_or_else(|| col_of(t, cur));
            *want_col = Some(col);
            let mut p = ls;
            let mut moved = 0;
            for _ in 0..n {
                if matches!(mk, Motion::Down) {
                    let e = line_end(t, p);
                    if e >= t.len() {
                        break;
                    }
                    p = e + 1;
                } else {
                    if p == 0 {
                        break;
                    }
                    p = line_start(t, p - 1);
                }
                moved += 1;
            }
            if moved == 0 {
                return None;
            }
            let target = if op.is_some() { p } else { pos_at_col(t, p, line_end(t, p), col) };
            Some(Reach { target, kind: Kind::Linewise })
        }
        Motion::WordFwd => {
            let cs: Chars = t.char_indices().collect();
            if cs.is_empty() {
                return None;
            }
            let idx = cs.partition_point(|(b, _)| *b < cur);
            if idx >= cs.len() {
                return None;
            }
            // `cw` on a word changes to the end of the word, like `ce`
            if op == Some(Op::Change) && class(cs[idx].1) != 0 {
                let mut e = idx;
                for step in 0..n {
                    e = if step == 0 {
                        run_end(&cs, idx)
                    } else {
                        word_end(&cs, e)
                    };
                }
                return incl(cs[e].0);
            }
            let mut i = idx;
            let mut last_start = idx;
            for _ in 0..n {
                last_start = i;
                i = word_fwd(&cs, i);
                if i >= cs.len() {
                    break;
                }
            }
            if op.is_some() {
                if i >= cs.len() {
                    return excl(t.len());
                }
                let sb = cs[last_start].0;
                if line_start(t, cs[i].0) != line_start(t, sb) {
                    // The last word moved over ends the line: stop there instead of eating the line break
                    let c0 = class(cs[last_start].1);
                    let target = if c0 != 0 {
                        let e = run_end(&cs, last_start);
                        if e + 1 >= cs.len() { t.len() } else { cs[e + 1].0 }
                    } else {
                        line_end(t, sb)
                    };
                    return excl(target);
                }
            }
            excl(if i >= cs.len() { t.len() } else { cs[i].0 })
        }
        Motion::WordBack => {
            let cs: Chars = t.char_indices().collect();
            let idx = cs.partition_point(|(b, _)| *b < cur);
            if cs.is_empty() || idx == 0 {
                return None;
            }
            let mut i = idx;
            for _ in 0..n {
                i = word_back(&cs, i);
            }
            excl(cs[i].0)
        }
        Motion::WordEnd => {
            let cs: Chars = t.char_indices().collect();
            if cs.is_empty() {
                return None;
            }
            let mut i = cs.partition_point(|(b, _)| *b < cur).min(cs.len() - 1);
            for _ in 0..n {
                i = word_end(&cs, i);
            }
            incl(cs[i].0)
        }
        Motion::LineStart => excl(ls),
        Motion::FirstNonBlank => excl(first_nonblank(t, ls, le)),
        Motion::LineEnd => {
            let lend = line_end_below(t, cur, n - 1);
            incl(last_char_pos(t, line_start(t, lend), lend))
        }
        Motion::FileStart | Motion::FileEnd => {
            let total = t.matches('\n').count() + 1;
            let line = match (mk, count) {
                (Motion::FileEnd, None) => total - 1,
                (_, None) => 0,
                (_, Some(c)) => c.clamp(1, total) - 1,
            };
            let start = nth_line_start(t, line);
            let target = if op.is_some() {
                start
            } else {
                first_nonblank(t, start, line_end(t, start))
            };
            Some(Reach { target, kind: Kind::Linewise })
        }
        Motion::Find(kind, ch, repeat) => match kind {
            FindKind::Find | FindKind::Till => {
                let mut start = if cur < le { next_pos(t, cur) } else { le };
                // `;` after `t` must not stick on the character it already sits before
                if repeat && kind == FindKind::Till && start < le && t[start..].starts_with(ch) {
                    start = next_pos(t, start);
                }
                let mut seen = 0;
                let mut p = start;
                while p < le {
                    let c = t[p..].chars().next()?;
                    if c == ch {
                        seen += 1;
                        if seen == n {
                            let target = if kind == FindKind::Find { p } else { prev_pos(t, p) };
                            return incl(target);
                        }
                    }
                    p += c.len_utf8();
                }
                None
            }
            FindKind::FindBack | FindKind::TillBack => {
                let mut it = t[ls..cur].char_indices().rev().peekable();
                if repeat
                    && kind == FindKind::TillBack
                    && it.peek().is_some_and(|&(_, c)| c == ch)
                {
                    it.next();
                }
                let (i, _) = it.filter(|&(_, c)| c == ch).nth(n - 1)?;
                let found = ls + i;
                excl(if kind == FindKind::FindBack { found } else { next_pos(t, found) })
            }
        },
    }
}

fn toggle_case(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_lowercase() {
                c.to_uppercase().collect::<String>()
            } else if c.is_uppercase() {
                c.to_lowercase().collect::<String>()
            } else {
                c.to_string()
            }
        })
        .collect()
}

// ---- state machine -------------------------------------------------------------------------------------------------

impl VimState {
    /// A state already in Normal mode, for tests.
    #[cfg(test)]
    pub(super) fn in_normal_mode() -> Self {
        Self {
            mode: VimMode::Normal,
            ..Self::default()
        }
    }

    pub(crate) fn mode(&self) -> VimMode {
        self.mode
    }

    /// Nothing to clean up: Insert mode with no open undo group and no half-typed command.
    pub(crate) fn is_idle(&self) -> bool {
        self.mode == VimMode::Insert
            && !self.group_open
            && self.pending == Pending::None
            && self.op.is_none()
            && self.count.is_none()
    }

    /// Drop all modal state and return to Insert, closing any open undo group.
    pub(crate) fn reset(&mut self, ta: &mut TextArea) {
        self.close_group(ta);
        self.mode = VimMode::Insert;
        self.clear_pending();
        self.want_col = None;
    }

    /// Close an open undo group; call before the text is replaced from outside the vim layer.
    pub(crate) fn close_group(&mut self, ta: &mut TextArea) {
        if self.group_open {
            ta.end_undo_group();
            self.group_open = false;
        }
    }

    fn open_group(&mut self, ta: &mut TextArea) {
        if !self.group_open {
            ta.begin_undo_group();
            self.group_open = true;
        }
    }

    /// After an edit: a command that stayed in Normal mode is one undo step; one that entered Insert keeps the group open until Esc.
    fn finish_edit(&mut self, ta: &mut TextArea) {
        if self.mode == VimMode::Normal {
            self.close_group(ta);
        }
    }

    fn clear_pending(&mut self) {
        self.count = None;
        self.op = None;
        self.op_count = None;
        self.pending = Pending::None;
    }

    fn total_count(&self) -> Option<usize> {
        match (self.op_count, self.count) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(1).saturating_mul(b.unwrap_or(1)).min(99_999)),
        }
    }

    fn enter_insert(&mut self, ta: &mut TextArea, pos: usize) {
        ta.set_cursor(pos);
        self.open_group(ta);
        self.mode = VimMode::Insert;
        self.clear_pending();
    }

    fn leave_insert(&mut self, ta: &mut TextArea) {
        // End the group before moving, so a bare `i` Esc leaves no undo entry
        self.close_group(ta);
        self.mode = VimMode::Normal;
        self.clear_pending();
        let t = ta.text().to_string();
        let cur = ta.cursor().min(t.len());
        if cur > line_start(&t, cur) {
            ta.set_cursor(prev_pos(&t, cur));
        }
    }

    /// Offer a key to the vim layer.
    pub(crate) fn handle_key(&mut self, ta: &mut TextArea, key: &KeyEvent) -> VimKey {
        let mods = key.modifiers.difference(KeyModifiers::SHIFT);
        match self.mode {
            VimMode::Insert => {
                if key.code == KeyCode::Esc && key.modifiers.is_empty() {
                    self.leave_insert(ta);
                    VimKey::Consumed
                } else {
                    VimKey::Pass
                }
            }
            VimMode::Normal => {
                if mods == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('r' | 'R')) {
                    let n = self.total_count().unwrap_or(1);
                    self.clear_pending();
                    self.want_col = None;
                    for _ in 0..n {
                        if !ta.redo() {
                            break;
                        }
                    }
                    self.clamp_cursor(ta);
                    return VimKey::Consumed;
                }
                if !mods.is_empty() {
                    // Other chords (Ctrl+C, Ctrl+L, Alt+Enter, ...) keep their usual meaning
                    return VimKey::Pass;
                }
                let c = match key.code {
                    KeyCode::Esc => {
                        self.clear_pending();
                        ta.clear_selection();
                        return VimKey::Consumed;
                    }
                    KeyCode::Char(c) => c,
                    KeyCode::Left | KeyCode::Backspace => 'h',
                    KeyCode::Right => 'l',
                    KeyCode::Home => '0',
                    KeyCode::End => '$',
                    KeyCode::Delete => 'x',
                    _ => {
                        // Enter submits, Tab changes focus, Up/Down browse history: all as today
                        self.clear_pending();
                        return VimKey::Pass;
                    }
                };
                self.normal_char(ta, c);
                VimKey::Consumed
            }
        }
    }

    fn clamp_cursor(&self, ta: &mut TextArea) {
        let t = ta.text().to_string();
        let cur = ta.cursor();
        let clamped = clamp_normal(&t, cur);
        if clamped != cur {
            ta.set_cursor(clamped);
        }
    }

    fn normal_char(&mut self, ta: &mut TextArea, c: char) {
        let t = ta.text().to_string();
        let cur = clamp_normal(&t, ta.cursor());
        if cur != ta.cursor() {
            ta.set_cursor(cur);
        }
        if !matches!(c, 'j' | 'k') {
            self.want_col = None;
        }
        match self.pending {
            Pending::Replace => {
                let n = self.total_count().unwrap_or(1);
                self.clear_pending();
                self.replace_chars(ta, &t, cur, c, n);
                return;
            }
            Pending::Find(kind) => {
                self.last_find = Some((kind, c));
                self.run_motion(ta, &t, cur, Motion::Find(kind, c, false));
                return;
            }
            Pending::G => {
                if c == 'g' {
                    self.run_motion(ta, &t, cur, Motion::FileStart);
                } else {
                    self.clear_pending();
                }
                return;
            }
            Pending::None => {}
        }
        if c.is_ascii_digit() && (c != '0' || self.count.is_some()) {
            let d = c as usize - '0' as usize;
            self.count = Some(
                self.count
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(d)
                    .min(99_999),
            );
            return;
        }
        match c {
            'd' | 'c' | 'y' => {
                let op = match c {
                    'd' => Op::Delete,
                    'c' => Op::Change,
                    _ => Op::Yank,
                };
                match self.op {
                    None => {
                        self.op = Some(op);
                        self.op_count = self.count.take();
                    }
                    Some(o) if o == op => {
                        let n = self.total_count().unwrap_or(1);
                        self.clear_pending();
                        self.line_op(ta, &t, cur, op, n);
                    }
                    Some(_) => self.clear_pending(),
                }
            }
            'h' => self.run_motion(ta, &t, cur, Motion::Left),
            'l' => self.run_motion(ta, &t, cur, Motion::Right),
            'j' => self.run_motion(ta, &t, cur, Motion::Down),
            'k' => self.run_motion(ta, &t, cur, Motion::Up),
            'w' => self.run_motion(ta, &t, cur, Motion::WordFwd),
            'b' => self.run_motion(ta, &t, cur, Motion::WordBack),
            'e' => self.run_motion(ta, &t, cur, Motion::WordEnd),
            '0' => self.run_motion(ta, &t, cur, Motion::LineStart),
            '^' => self.run_motion(ta, &t, cur, Motion::FirstNonBlank),
            '$' => self.run_motion(ta, &t, cur, Motion::LineEnd),
            'G' => self.run_motion(ta, &t, cur, Motion::FileEnd),
            'g' => self.pending = Pending::G,
            'f' => self.pending = Pending::Find(FindKind::Find),
            't' => self.pending = Pending::Find(FindKind::Till),
            'F' => self.pending = Pending::Find(FindKind::FindBack),
            'T' => self.pending = Pending::Find(FindKind::TillBack),
            ';' | ',' => match self.last_find {
                Some((kind, ch)) => {
                    let kind = if c == ',' { kind.reversed() } else { kind };
                    self.run_motion(ta, &t, cur, Motion::Find(kind, ch, true));
                }
                None => self.clear_pending(),
            },
            _ if self.op.is_some() => self.clear_pending(),
            'x' => self.op_motion(ta, &t, cur, Op::Delete, Motion::Right),
            'X' => self.op_motion(ta, &t, cur, Op::Delete, Motion::Left),
            'D' => self.op_motion(ta, &t, cur, Op::Delete, Motion::LineEnd),
            'C' => self.op_motion(ta, &t, cur, Op::Change, Motion::LineEnd),
            's' => {
                if cur >= line_end(&t, cur) {
                    self.clear_pending();
                    self.enter_insert(ta, cur);
                } else {
                    self.op_motion(ta, &t, cur, Op::Change, Motion::Right);
                }
            }
            'S' => {
                let n = self.total_count().unwrap_or(1);
                self.clear_pending();
                self.line_op(ta, &t, cur, Op::Change, n);
            }
            'Y' => {
                let n = self.total_count().unwrap_or(1);
                self.clear_pending();
                self.line_op(ta, &t, cur, Op::Yank, n);
            }
            'p' | 'P' => {
                let n = self.total_count().unwrap_or(1);
                self.clear_pending();
                self.put(ta, &t, cur, c == 'p', n);
            }
            'r' => self.pending = Pending::Replace,
            'J' => {
                let n = self.total_count().unwrap_or(2).max(2);
                self.clear_pending();
                self.join(ta, cur, n);
            }
            '~' => {
                let n = self.total_count().unwrap_or(1);
                self.clear_pending();
                self.tilde(ta, &t, cur, n);
            }
            'u' => {
                let n = self.total_count().unwrap_or(1);
                self.clear_pending();
                for _ in 0..n {
                    if !ta.undo() {
                        break;
                    }
                }
                self.clamp_cursor(ta);
            }
            'i' => self.enter_insert(ta, cur),
            'a' => {
                let pos = if cur < line_end(&t, cur) { next_pos(&t, cur) } else { cur };
                self.enter_insert(ta, pos);
            }
            'A' => self.enter_insert(ta, line_end(&t, cur)),
            'I' => {
                let ls = line_start(&t, cur);
                let le = line_end(&t, cur);
                let mut p = ls;
                while p < le && matches!(t.as_bytes()[p], b' ' | b'\t') {
                    p += 1;
                }
                self.enter_insert(ta, p);
            }
            'o' | 'O' => {
                let below = c == 'o';
                let at = if below { line_end(&t, cur) } else { line_start(&t, cur) };
                self.clear_pending();
                self.open_group(ta);
                ta.replace_range(at..at, "\n");
                ta.set_cursor(if below { at + 1 } else { at });
                self.mode = VimMode::Insert;
            }
            // Unmapped keys do nothing in Normal mode (they never type)
            _ => self.clear_pending(),
        }
    }

    /// `x`/`X`/`D`/`C`/`s`: an operator plus a motion, honouring a typed count.
    fn op_motion(&mut self, ta: &mut TextArea, t: &str, cur: usize, op: Op, mk: Motion) {
        self.op = Some(op);
        self.run_motion(ta, t, cur, mk);
    }

    fn run_motion(&mut self, ta: &mut TextArea, t: &str, cur: usize, mk: Motion) {
        let count = self.total_count();
        let op = self.op;
        self.clear_pending();
        let mut want_col = self.want_col;
        let found = reach(t, cur, mk, count, op, &mut want_col);
        self.want_col = if matches!(mk, Motion::Down | Motion::Up) {
            want_col
        } else {
            None
        };
        let Some(reach) = found else { return };
        match op {
            None => ta.set_cursor(clamp_normal(t, reach.target)),
            Some(op) => self.apply_op(ta, t, cur, op, reach),
        }
    }

    fn apply_op(&mut self, ta: &mut TextArea, t: &str, cur: usize, op: Op, r: Reach) {
        let lo = cur.min(r.target);
        let hi = cur.max(r.target);
        match r.kind {
            Kind::Linewise => {
                let a = line_start(t, lo);
                let b = line_end(t, hi);
                self.line_range_op(ta, t, cur, op, a, b);
            }
            Kind::Exclusive => self.char_range_op(ta, t, op, lo, hi),
            Kind::Inclusive => {
                let end = if hi < t.len() && t.as_bytes()[hi] != b'\n' {
                    next_pos(t, hi)
                } else {
                    hi
                };
                self.char_range_op(ta, t, op, lo, end);
            }
        }
    }

    /// `dd`/`cc`/`yy` over `n` lines.
    fn line_op(&mut self, ta: &mut TextArea, t: &str, cur: usize, op: Op, n: usize) {
        let a = line_start(t, cur);
        let b = line_end_below(t, cur, n.saturating_sub(1));
        self.line_range_op(ta, t, cur, op, a, b);
    }

    /// Operate on whole lines: `a` is the start of the first, `b` the end (before the newline) of the last.
    fn line_range_op(&mut self, ta: &mut TextArea, t: &str, cur: usize, op: Op, a: usize, b: usize) {
        self.reg_text = format!("{}\n", &t[a..b]);
        self.reg_linewise = true;
        match op {
            Op::Yank => {
                if a < line_start(t, cur) {
                    let col = col_of(t, cur);
                    ta.set_cursor(pos_at_col(t, a, line_end(t, a), col));
                }
            }
            Op::Delete => {
                self.open_group(ta);
                let (ds, de) = if b < t.len() {
                    (a, b + 1)
                } else if a > 0 {
                    (a - 1, b)
                } else {
                    (a, b)
                };
                ta.replace_range(ds..de, "");
                let nt = ta.text().to_string();
                let pos = if b < t.len() { a } else { line_start(&nt, ds.min(nt.len())) };
                let pos = pos.min(nt.len());
                ta.set_cursor(first_nonblank(&nt, pos, line_end(&nt, pos)));
                self.finish_edit(ta);
            }
            Op::Change => {
                self.open_group(ta);
                ta.replace_range(a..b, "");
                ta.set_cursor(a);
                self.mode = VimMode::Insert;
            }
        }
    }

    fn char_range_op(&mut self, ta: &mut TextArea, t: &str, op: Op, s: usize, e: usize) {
        if s >= e {
            if op == Op::Change {
                self.enter_insert(ta, s);
            }
            return;
        }
        self.reg_text = t[s..e].to_string();
        self.reg_linewise = false;
        match op {
            Op::Yank => ta.set_cursor(clamp_normal(t, s)),
            Op::Delete => {
                self.open_group(ta);
                ta.replace_range(s..e, "");
                let nt = ta.text().to_string();
                ta.set_cursor(clamp_normal(&nt, s));
                self.finish_edit(ta);
            }
            Op::Change => {
                self.open_group(ta);
                ta.replace_range(s..e, "");
                ta.set_cursor(s);
                self.mode = VimMode::Insert;
            }
        }
    }

    fn put(&mut self, ta: &mut TextArea, t: &str, cur: usize, after: bool, n: usize) {
        if self.reg_text.is_empty() {
            return;
        }
        self.open_group(ta);
        if self.reg_linewise {
            let body = self.reg_text.strip_suffix('\n').unwrap_or(&self.reg_text);
            let rep = vec![body; n].join("\n");
            let (at, text, start) = if after {
                let le = line_end(t, cur);
                (le, format!("\n{rep}"), le + 1)
            } else {
                let ls = line_start(t, cur);
                (ls, format!("{rep}\n"), ls)
            };
            ta.replace_range(at..at, &text);
            let nt = ta.text().to_string();
            ta.set_cursor(first_nonblank(&nt, start, line_end(&nt, start)));
        } else {
            let rep = self.reg_text.repeat(n);
            let at = if after && cur < line_end(t, cur) { next_pos(t, cur) } else { cur };
            ta.replace_range(at..at, &rep);
            let nt = ta.text().to_string();
            let pos = if rep.contains('\n') { at } else { prev_pos(&nt, at + rep.len()) };
            ta.set_cursor(clamp_normal(&nt, pos));
        }
        self.finish_edit(ta);
    }

    fn replace_chars(&mut self, ta: &mut TextArea, t: &str, cur: usize, c: char, n: usize) {
        let le = line_end(t, cur);
        let mut e = cur;
        for _ in 0..n {
            if e >= le {
                return;
            }
            e = next_pos(t, e);
        }
        self.open_group(ta);
        let rep = c.to_string().repeat(n);
        ta.replace_range(cur..e, &rep);
        ta.set_cursor(cur + rep.len() - c.len_utf8());
        self.finish_edit(ta);
    }

    fn tilde(&mut self, ta: &mut TextArea, t: &str, cur: usize, n: usize) {
        let le = line_end(t, cur);
        let mut e = cur;
        for _ in 0..n {
            if e >= le {
                break;
            }
            e = next_pos(t, e);
        }
        if e == cur {
            return;
        }
        self.open_group(ta);
        let toggled = toggle_case(&t[cur..e]);
        ta.replace_range(cur..e, &toggled);
        let nt = ta.text().to_string();
        ta.set_cursor(clamp_normal(&nt, cur + toggled.len()));
        self.finish_edit(ta);
    }

    fn join(&mut self, ta: &mut TextArea, cur: usize, n: usize) {
        self.open_group(ta);
        let mut lp = cur;
        let mut at = None;
        for _ in 0..n.saturating_sub(1) {
            let t = ta.text().to_string();
            let le = line_end(&t, lp);
            if le >= t.len() {
                break;
            }
            let mut j = le + 1;
            while j < t.len() && matches!(t.as_bytes()[j], b' ' | b'\t') {
                j += 1;
            }
            let rest_blank_or_paren =
                j >= t.len() || t.as_bytes()[j] == b'\n' || t.as_bytes()[j] == b')';
            let head = &t[line_start(&t, le)..le];
            let sep = if rest_blank_or_paren || head.is_empty() || head.ends_with([' ', '\t']) {
                ""
            } else {
                " "
            };
            ta.replace_range(le..j, sep);
            lp = le;
            at = Some(le);
        }
        if let Some(at) = at {
            let nt = ta.text().to_string();
            ta.set_cursor(clamp_normal(&nt, at));
        }
        self.finish_edit(ta);
    }
}
