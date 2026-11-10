//! Unit tests for the prompt vim engine: motions, operators, counts, registers, undo and mode switching.

use super::vim::{VimKey, VimMode, VimState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use fuigo_ratatui_textarea::TextArea;

fn key(code: KeyCode, m: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, m)
}

fn parse_keys(keys: &str) -> Vec<KeyEvent> {
    let mut out = Vec::new();
    let mut it = keys.chars();
    while let Some(c) = it.next() {
        if c == '<' {
            let name: String = it.by_ref().take_while(|&d| d != '>').collect();
            out.push(match name.as_str() {
                "Esc" => key(KeyCode::Esc, KeyModifiers::NONE),
                "C-r" => key(KeyCode::Char('r'), KeyModifiers::CONTROL),
                "C-c" => key(KeyCode::Char('c'), KeyModifiers::CONTROL),
                "BS" => key(KeyCode::Backspace, KeyModifiers::NONE),
                "Del" => key(KeyCode::Delete, KeyModifiers::NONE),
                "Left" => key(KeyCode::Left, KeyModifiers::NONE),
                "Right" => key(KeyCode::Right, KeyModifiers::NONE),
                "Up" => key(KeyCode::Up, KeyModifiers::NONE),
                "Home" => key(KeyCode::Home, KeyModifiers::NONE),
                "End" => key(KeyCode::End, KeyModifiers::NONE),
                "CR" => key(KeyCode::Enter, KeyModifiers::NONE),
                "Tab" => key(KeyCode::Tab, KeyModifiers::NONE),
                other => panic!("unknown key <{other}>"),
            });
        } else {
            let m = if c.is_uppercase() {
                KeyModifiers::SHIFT
            } else {
                KeyModifiers::NONE
            };
            out.push(key(KeyCode::Char(c), m));
        }
    }
    out
}

struct Harness {
    ta: TextArea,
    vim: VimState,
}

impl Harness {
    /// `spec` marks the cursor with `|`; the engine starts in Normal mode.
    fn new(spec: &str) -> Self {
        let pos = spec.find('|').expect("cursor marker");
        let text = spec.replacen('|', "", 1);
        let mut ta = TextArea::new();
        ta.set_text(&text);
        ta.set_cursor(pos);
        // The initial text is not an undoable edit
        ta.clear_history();
        let mut vim = VimState::default();
        vim.mode = VimMode::Normal;
        Self { ta, vim }
    }

    fn feed(&mut self, keys: &str) {
        for k in parse_keys(keys) {
            if self.vim.handle_key(&mut self.ta, &k) == VimKey::Pass
                && self.vim.mode() == VimMode::Insert
            {
                self.ta.input(k);
            }
        }
    }

    fn render(&self) -> String {
        let t = self.ta.text();
        let c = self.ta.cursor();
        format!("{}|{}", &t[..c], &t[c..])
    }
}

fn run(spec: &str, keys: &str) -> String {
    let mut h = Harness::new(spec);
    h.feed(keys);
    h.render()
}

#[test]
fn motions_h_l() {
    assert_eq!(run("a|bc", "l"), "ab|c");
    assert_eq!(run("ab|c", "l"), "ab|c");
    assert_eq!(run("ab|c", "h"), "a|bc");
    assert_eq!(run("|abc", "h"), "|abc");
    assert_eq!(run("|abcd", "3l"), "abc|d");
    assert_eq!(run("|abcd", "9l"), "abc|d");
    assert_eq!(run("a|b\ncd", "l"), "a|b\ncd");
}

#[test]
fn motions_j_k_keep_column() {
    assert_eq!(run("|ab\ncd", "j"), "ab\n|cd");
    assert_eq!(run("a|bc\nd\nefg", "jj"), "abc\nd\ne|fg");
    assert_eq!(run("a|bc\nd\nefg", "jjkk"), "a|bc\nd\nefg");
    assert_eq!(run("|ab", "j"), "|ab");
    assert_eq!(run("|ab", "k"), "|ab");
    assert_eq!(run("|a\nb\nc\nd", "2j"), "a\nb\n|c\nd");
}

#[test]
fn motions_w_b_e() {
    assert_eq!(run("|foo bar baz", "w"), "foo |bar baz");
    assert_eq!(run("|foo bar baz", "2w"), "foo bar |baz");
    assert_eq!(run("|foo.bar", "ww"), "foo.|bar");
    assert_eq!(run("|foo\nbar", "w"), "foo\n|bar");
    assert_eq!(run("foo |bar", "w"), "foo ba|r");
    assert_eq!(run("foo ba|r", "b"), "foo |bar");
    assert_eq!(run("foo ba|r", "bb"), "|foo bar");
    assert_eq!(run("foo bar ba|z", "2b"), "foo |bar baz");
    assert_eq!(run("|foo bar", "e"), "fo|o bar");
    assert_eq!(run("|foo bar", "ee"), "foo ba|r");
    assert_eq!(run("|foo bar baz", "2e"), "foo ba|r baz");
}

#[test]
fn motions_line_and_file() {
    assert_eq!(run("  fo|o bar", "0"), "|  foo bar");
    assert_eq!(run("  fo|o bar", "^"), "  |foo bar");
    assert_eq!(run("  fo|o bar", "$"), "  foo ba|r");
    assert_eq!(run("a\nb\n|c", "gg"), "|a\nb\nc");
    assert_eq!(run("|a\nb\nc", "G"), "a\nb\n|c");
    assert_eq!(run("|a\nb\nc", "2G"), "a\n|b\nc");
    assert_eq!(run("a\nb\n|c", "2gg"), "a\n|b\nc");
    assert_eq!(run("a\nb\n  |c", "gg"), "|a\nb\n  c");
    assert_eq!(run("|a\nb\n  c", "G"), "a\nb\n  |c");
    assert_eq!(run("|ab\ncd\nef", "2$"), "ab\nc|d\nef");
}

#[test]
fn motions_find_till_and_repeat() {
    assert_eq!(run("|a,b,c,d", "f,"), "a|,b,c,d");
    assert_eq!(run("|a,b,c,d", "2f,"), "a,b|,c,d");
    assert_eq!(run("|ab,cd", "t,"), "a|b,cd");
    assert_eq!(run("ab,c|d", "F,"), "ab|,cd");
    assert_eq!(run("ab,c|d", "T,"), "ab,|cd");
    assert_eq!(run("|abc", "fz"), "|abc");
    assert_eq!(run("|a,b,c,d", "f,;"), "a,b|,c,d");
    assert_eq!(run("|a,b,c,d", "f,;,"), "a|,b,c,d");
    // `;` after `t` does not stick on the character it already precedes
    assert_eq!(run("|a,b,c,d", "t,;"), "a,|b,c,d");
    // a find stays on its line
    assert_eq!(run("|ab\nc,d", "f,"), "|ab\nc,d");
}

#[test]
fn operator_d_with_motions() {
    assert_eq!(run("|foo bar", "dw"), "|bar");
    assert_eq!(run("|a b c", "d2w"), "|c");
    assert_eq!(run("|a b c", "2dw"), "|c");
    assert_eq!(run("|a b c d e", "2d2w"), "|e");
    // the last word on a line does not swallow the line break
    assert_eq!(run("foo |bar\nbaz", "dw"), "foo| \nbaz");
    assert_eq!(run("foo |bar", "d0"), "|bar");
    assert_eq!(run("fo|o bar", "D"), "f|o");
    assert_eq!(run("fo|o bar", "d$"), "f|o");
    assert_eq!(run("|foo bar", "de"), "| bar");
    assert_eq!(run("foo ba|r", "db"), "foo |r");
    assert_eq!(run("|a,b,c", "df,"), "|b,c");
    assert_eq!(run("|a,b,c", "dt,"), "|,b,c");
    assert_eq!(run("a,b|,c", "dF,"), "a|,c");
    assert_eq!(run("|abc", "dl"), "|bc");
    assert_eq!(run("a|bc", "dh"), "|bc");
    assert_eq!(run("a|bc", "d^"), "|bc");
}

#[test]
fn operator_d_linewise() {
    assert_eq!(run("a\n|b\nc", "dd"), "a\n|c");
    assert_eq!(run("a\n|b", "dd"), "|a");
    assert_eq!(run("|a", "dd"), "|");
    assert_eq!(run("|a\nb\nc", "2dd"), "|c");
    assert_eq!(run("a\n|b\nc\nd", "dj"), "a\n|d");
    assert_eq!(run("a\nb\n|c", "dk"), "|a");
    assert_eq!(run("a\n|b\nc", "dG"), "|a");
    assert_eq!(run("a\n|b\nc", "dgg"), "|c");
    assert_eq!(run("a\n  |b\nc", "dd"), "a\n|c");
    assert_eq!(run("a\n|b\n  c", "dd"), "a\n  |c");
}

#[test]
fn operator_c() {
    assert_eq!(run("|foo bar", "cwX<Esc>"), "|X bar");
    assert_eq!(run("fo|o bar", "cwX<Esc>"), "fo|X bar");
    assert_eq!(run("|foo bar", "c2wX<Esc>"), "|X");
    assert_eq!(run("foo\n|bar", "ccX<Esc>"), "foo\n|X");
    assert_eq!(run("fo|o bar", "C!<Esc>"), "fo|!");
    assert_eq!(run("|foo bar", "cet<Esc>"), "|t bar");
    assert_eq!(run("a|bc", "sX<Esc>"), "a|Xc");
    assert_eq!(run("a\n|b\nc", "SX<Esc>"), "a\n|X\nc");
    assert_eq!(run("|a,b", "ct,X<Esc>"), "|X,b");
}

#[test]
fn operator_y_and_put() {
    assert_eq!(run("|a\nb", "yyp"), "a\n|a\nb");
    assert_eq!(run("a\n|b", "yyP"), "a\n|b\nb");
    assert_eq!(run("|foo bar", "ywP"), "foo| foo bar");
    assert_eq!(run("|foo bar", "ywwP"), "foo foo| bar");
    assert_eq!(run("|ab", "xp"), "b|a");
    assert_eq!(run("|ab", "xP"), "|ab");
    assert_eq!(run("|ab", "yl2p"), "aa|ab");
    assert_eq!(run("|a\nb", "ddp"), "b\n|a");
    assert_eq!(run("|a\nb", "yyjp"), "a\nb\n|a");
    assert_eq!(run("|a\nb", "2yyP"), "|a\nb\na\nb");
    assert_eq!(run("a|b", "Yp"), "ab\n|ab");
    // an empty register does nothing
    assert_eq!(run("|ab", "p"), "|ab");
    // yank does not change the text and keeps the cursor for yy
    assert_eq!(run("a|bc", "yy"), "a|bc");
    assert_eq!(run("a\nb|c", "yk"), "|a\nbc");
}

#[test]
fn x_r_j_tilde() {
    assert_eq!(run("|abcd", "2x"), "|cd");
    assert_eq!(run("ab|c", "x"), "a|b");
    assert_eq!(run("|", "x"), "|");
    assert_eq!(run("a|bc", "X"), "|bc");
    assert_eq!(run("|abc", "rx"), "|xbc");
    assert_eq!(run("|abc", "3rx"), "xx|x");
    assert_eq!(run("|ab", "3rx"), "|ab");
    assert_eq!(run("a|b\n  cd", "J"), "ab| cd");
    assert_eq!(run("|a\nb\nc", "3J"), "a b| c");
    assert_eq!(run("|a \nb", "J"), "a |b");
    assert_eq!(run("|a\n)", "J"), "a|)");
    assert_eq!(run("|a", "J"), "|a");
    assert_eq!(run("|aBc", "3~"), "Ab|C");
    assert_eq!(run("|ab", "~"), "A|b");
    assert_eq!(run("a|B", "~"), "a|b");
}

#[test]
fn counts() {
    assert_eq!(run("|abcdef", "3x"), "|def");
    assert_eq!(run("|abcdef", "12l"), "abcde|f");
    assert_eq!(run("|a b c d e f", "10x"), "|f");
    assert_eq!(run("|a b c d e", "2d2w"), "|e");
    assert_eq!(run("|a\nb\nc\nd", "3dd"), "|d");
    assert_eq!(run("|a\nb\nc\nd", "d3j"), "|");
    assert_eq!(run("|abc", "0l"), "a|bc");
    // 0 is a motion until a digit precedes it
    assert_eq!(run("a|bc", "0"), "|abc");
    assert_eq!(run("|abcdefghijkl", "10l"), "abcdefghij|kl");
}

#[test]
fn undo_and_redo() {
    assert_eq!(run("|abc", "xu"), "|abc");
    assert_eq!(run("|abc", "xu<C-r>"), "|bc");
    assert_eq!(run("|abcd", "xxxu"), "|cd");
    assert_eq!(run("|abcd", "xxx2u"), "|bcd");
    assert_eq!(run("|abcd", "xxx3u"), "|abcd");
    assert_eq!(run("|abcd", "xxx3u2<C-r>"), "|cd");
    // nothing to undo is a no-op
    assert_eq!(run("|abc", "u"), "|abc");
    assert_eq!(run("|abc", "<C-r>"), "|abc");
    // an Insert session is a single undo step
    assert_eq!(run("|ab", "ixy<Esc>u"), "|ab");
    assert_eq!(run("|a", "ox<Esc>u"), "|a");
    assert_eq!(run("|foo bar", "cwxyz<Esc>u"), "|foo bar");
    assert_eq!(run("|foo bar", "dwu"), "|foo bar");
    assert_eq!(run("|a\nb", "ddu"), "|a\nb");
    assert_eq!(run("|ab", "ixy<Esc>u<C-r>"), "x|yab");
}

#[test]
fn entering_insert_and_leaving() {
    assert_eq!(run("|ab", "iX<Esc>"), "|Xab");
    assert_eq!(run("|ab", "aX<Esc>"), "a|Xb");
    assert_eq!(run("|ab", "AX<Esc>"), "ab|X");
    assert_eq!(run("  |ab", "IX<Esc>"), "  |Xab");
    assert_eq!(run("|a\nb", "ox<Esc>"), "a\n|x\nb");
    assert_eq!(run("a\n|b", "Ox<Esc>"), "a\n|x\nb");
    // Esc at the start of a line does not move before it
    assert_eq!(run("|ab", "i<Esc>"), "|ab");
    // `a` on an empty line stays put
    assert_eq!(run("|", "ax<Esc>"), "|x");
}

#[test]
fn mode_transitions() {
    let mut h = Harness::new("a|b");
    assert_eq!(h.vim.mode(), VimMode::Normal);
    h.feed("i");
    assert_eq!(h.vim.mode(), VimMode::Insert);
    h.feed("<Esc>");
    assert_eq!(h.vim.mode(), VimMode::Normal);
    h.feed("A");
    assert_eq!(h.vim.mode(), VimMode::Insert);
    // Esc in Insert is consumed once; typing in Insert is left to the normal prompt handling
    let k = key(KeyCode::Char('x'), KeyModifiers::NONE);
    assert_eq!(h.vim.handle_key(&mut h.ta, &k), VimKey::Pass);
    let esc = key(KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(h.vim.handle_key(&mut h.ta, &esc), VimKey::Consumed);
    assert_eq!(h.vim.mode(), VimMode::Normal);
    assert_eq!(VimMode::Normal.label(), "NORMAL");
    assert_eq!(VimMode::Insert.label(), "INSERT");
}

#[test]
fn normal_mode_esc_is_consumed_and_clears_pending() {
    let mut h = Harness::new("|abc def");
    let esc = key(KeyCode::Esc, KeyModifiers::NONE);
    assert_eq!(h.vim.handle_key(&mut h.ta, &esc), VimKey::Consumed);
    assert_eq!(h.vim.mode(), VimMode::Normal);
    // a pending operator and count are dropped by Esc
    h.feed("2d<Esc>x");
    assert_eq!(h.render(), "|bc def");
}

#[test]
fn normal_mode_passes_submit_focus_and_chords() {
    let mut h = Harness::new("|abc");
    for k in ["<CR>", "<Tab>", "<C-c>", "<Up>"] {
        let ev = parse_keys(k).remove(0);
        assert_eq!(h.vim.handle_key(&mut h.ta, &ev), VimKey::Pass, "{k}");
    }
    assert_eq!(h.render(), "|abc");
}

#[test]
fn unmapped_keys_never_type() {
    assert_eq!(run("|ab", "zq"), "|ab");
    assert_eq!(run("|ab", "d z"), "|ab");
    let mut h = Harness::new("|ab");
    h.feed("zq");
    assert_eq!(h.vim.mode(), VimMode::Normal);
}

#[test]
fn arrow_keys_map_to_motions() {
    assert_eq!(run("|abc", "<Right>"), "a|bc");
    assert_eq!(run("a|bc", "<Left>"), "|abc");
    assert_eq!(run("a|bc", "<BS>"), "|abc");
    assert_eq!(run("a|bc", "<Del>"), "a|c");
    assert_eq!(run("a|bc", "<Home>"), "|abc");
    assert_eq!(run("a|bc", "<End>"), "ab|c");
}

#[test]
fn cancelled_operator_does_not_leak() {
    // `dy` cancels, then `x` is a fresh command
    assert_eq!(run("|ab", "dyx"), "|b");
    // an operator followed by a failing motion cancels and leaves the text alone
    assert_eq!(run("|ab", "dfz"), "|ab");
    assert_eq!(run("|ab", "dfzx"), "|b");
}

#[test]
fn multibyte_text() {
    assert_eq!(run("|héllo wörld", "w"), "héllo |wörld");
    assert_eq!(run("h|éllo", "x"), "h|llo");
    assert_eq!(run("|héllo", "$"), "héll|o");
    assert_eq!(run("|héllo", "fl"), "hé|llo");
    assert_eq!(run("|ab", "ré"), "|éb");
}

#[test]
fn reset_returns_to_insert_and_closes_the_undo_group() {
    let mut h = Harness::new("|ab");
    h.feed("i");
    assert_eq!(h.vim.mode(), VimMode::Insert);
    h.vim.reset(&mut h.ta);
    assert_eq!(h.vim.mode(), VimMode::Insert);
    // the group was closed, so a fresh Normal-mode edit is its own step
    h.feed("<Esc>x");
    assert_eq!(h.render(), "|b");
    h.feed("u");
    assert_eq!(h.render(), "|ab");
}
