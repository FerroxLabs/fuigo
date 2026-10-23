//! `/stoke` -- hidden easter egg. A full-screen demoscene fire, blown right by the wind, with the Wind mark above it.
//!
//! The fire is the classic aafire averaging: heat is seeded on the bottom two rows and every cell becomes the mean of the cells below it,
//! sampled from the down-left so the flames lean right. It runs on the ratatui frame loop (no alternate screen of its own) and only ticks
//! while the overlay is open. It never touches the session or the model: the state lives beside the agent view and closing it drops it.

use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;

use crate::theme::color_support::ColorLevel;

/// Heat glyphs, coldest to hottest.
pub(crate) const CHARS: &str = " .'`^,:;-~=+*xsS#%$@";
const GLYPHS: [&str; 20] = [
    " ", ".", "'", "`", "^", ",", ":", ";", "-", "~", "=", "+", "*", "x", "s", "S", "#", "%", "$",
    "@",
];
/// 256-colour ember ramp, one entry per glyph: black, deep red, red, orange, amber, yellow, white.
pub(crate) const RAMP: [u8; 20] = [
    16, 52, 52, 88, 88, 124, 160, 160, 196, 202, 202, 208, 208, 214, 214, 220, 220, 226, 229, 231,
];
/// Mark colours: white over the cool part of the fire, pale yellow over the hot part.
const MARK_COOL: (u8, u8, u8) = (255, 255, 255);
const MARK_HOT: (u8, u8, u8) = (255, 255, 215);
const LABEL: &str = " fuigo  ·  q to quit ";
const LABEL_GREY: u8 = 245;

/// Steps run before the single static frame shown when animations are off.
pub(crate) const STATIC_WARMUP: usize = 60;
/// Frame interval at 30 fps.
pub(crate) const FRAME_INTERVAL: Duration = Duration::from_millis(33);
/// Frame interval at 15 fps, used over SSH where every frame crosses the wire.
pub(crate) const FRAME_INTERVAL_SSH: Duration = Duration::from_millis(66);

/// Whether this process runs inside an SSH session.
pub(crate) fn is_ssh() -> bool {
    ["SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"]
        .iter()
        .any(|k| std::env::var_os(k).is_some())
}

/// A tiny xorshift64* generator. Seeded, so the fire is reproducible in tests.
#[derive(Clone, Debug)]
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
}

/// The heat field: `w` columns by `h` visible rows, plus two fuel rows below the visible area.
#[derive(Clone, Debug)]
pub(crate) struct Fire {
    w: usize,
    h: usize,
    heat: Vec<u8>,
    rng: Rng,
}

impl Fire {
    pub(crate) fn new(w: usize, h: usize, seed: u64) -> Self {
        Self {
            w,
            h,
            heat: vec![0; w * (h + 2)],
            rng: Rng::new(seed),
        }
    }

    pub(crate) fn size(&self) -> (usize, usize) {
        (self.w, self.h)
    }

    /// Heat at a visible cell.
    pub(crate) fn at(&self, x: usize, y: usize) -> u8 {
        self.heat[y * self.w + x]
    }

    /// Set heat anywhere in the field, including the two fuel rows (`y == h` and `y == h + 1`).
    pub(crate) fn set(&mut self, x: usize, y: usize, v: u8) {
        self.heat[y * self.w + x] = v;
    }

    /// One frame: re-seed the fuel rows, then propagate.
    pub(crate) fn step(&mut self) {
        self.fuel();
        self.propagate();
    }

    /// Random hot spots along the bottom two rows: 60% of columns are re-rolled each frame.
    fn fuel(&mut self) {
        let base = self.w * self.h;
        for x in 0..self.w {
            let r = self.rng.next_u32();
            if r % 100 < 60 {
                self.heat[base + x] = [0, 0, 70, 90, 110][(r / 100 % 5) as usize];
            }
            self.heat[base + self.w + x] = self.heat[base + x];
        }
    }

    /// The aafire average: below, twice below-left, below-right and two-below, over five, minus one for cooling.
    /// Weighting the left neighbour double pulls heat from the left, so flames drift right as they rise.
    /// Rows are updated top-down, so each row reads the previous frame's rows below it.
    pub(crate) fn propagate(&mut self) {
        let w = self.w;
        for i in 0..w * self.h {
            let x = i % w;
            let below = i + w;
            let l = if x > 0 { below - 1 } else { below };
            let r = if x + 1 < w { below + 1 } else { below };
            let sum = u16::from(self.heat[below])
                + 2 * u16::from(self.heat[l])
                + u16::from(self.heat[r])
                + u16::from(self.heat[below + w]);
            let v = (sum / 5) as u8;
            self.heat[i] = v.saturating_sub(1);
        }
    }

    /// Heat-weighted centre of mass across the visible rows, as `(x, y)`. `None` when everything is cold.
    pub(crate) fn centre_of_mass(&self) -> Option<(f64, f64)> {
        let (mut sx, mut sy, mut total) = (0.0, 0.0, 0.0);
        for y in 0..self.h {
            for x in 0..self.w {
                let v = f64::from(self.heat[y * self.w + x]);
                sx += v * x as f64;
                sy += v * y as f64;
                total += v;
            }
        }
        (total > 0.0).then(|| (sx / total, sy / total))
    }
}

/// How the overlay paints: the colour depth and whether the mark may use braille.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StokeStyle {
    pub(crate) color: ColorLevel,
    /// Legacy Windows console: fonts lack the braille block, so the mark is drawn as ASCII.
    pub(crate) ascii_mark: bool,
    /// `ui.animations`: when false the fire is warmed up once and shown as a single static frame.
    pub(crate) animated: bool,
}

impl StokeStyle {
    pub(crate) fn detect() -> Self {
        Self {
            color: crate::theme::color_support::get(),
            ascii_mark: crate::glyphs::is_legacy_windows_console(),
            animated: crate::appearance::cache::load_animations(),
        }
    }
}

/// The open overlay: the fire, its pacing, and how to paint it.
#[derive(Debug)]
pub(crate) struct StokeState {
    fire: Fire,
    seed: u64,
    interval: Duration,
    last_step: Option<Instant>,
    style: StokeStyle,
}

/// What a key does to the overlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StokeKeyOutcome {
    Close,
    Ignored,
}

impl StokeState {
    pub(crate) fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x5EED, |d| d.as_nanos() as u64);
        let interval = if is_ssh() {
            FRAME_INTERVAL_SSH
        } else {
            FRAME_INTERVAL
        };
        Self::with(seed, interval, StokeStyle::detect())
    }

    pub(crate) fn with(seed: u64, interval: Duration, style: StokeStyle) -> Self {
        Self {
            fire: Fire::new(0, 0, seed),
            seed,
            interval,
            last_step: None,
            style,
        }
    }

    pub(crate) fn interval(&self) -> Duration {
        self.interval
    }

    pub(crate) fn fire(&self) -> &Fire {
        &self.fire
    }

    pub(crate) fn fire_mut(&mut self) -> &mut Fire {
        &mut self.fire
    }

    /// Advance the fire if a full frame interval has passed since the last step. Returns whether it stepped,
    /// so the caller redraws only then: faster ticks never raise the frame rate above the cap.
    pub(crate) fn tick_at(&mut self, now: Instant) -> bool {
        if !self.style.animated {
            return false;
        }
        if let Some(last) = self.last_step
            && now.saturating_duration_since(last) < self.interval
        {
            return false;
        }
        self.last_step = Some(now);
        self.fire.step();
        true
    }

    /// q, Esc and Ctrl-C close; every other key is swallowed.
    pub(crate) fn handle_key(key: &crossterm::event::KeyEvent) -> StokeKeyOutcome {
        use crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => StokeKeyOutcome::Close,
            KeyCode::Char('q' | 'Q') if !ctrl => StokeKeyOutcome::Close,
            KeyCode::Char('c' | 'C') if ctrl => StokeKeyOutcome::Close,
            _ => StokeKeyOutcome::Ignored,
        }
    }

    /// Paint the whole of `area`: fire, then the mark above it, then the label on the bottom row.
    pub(crate) fn paint(&mut self, buf: &mut Buffer, area: Rect) {
        let (w, h) = (usize::from(area.width), usize::from(area.height));
        if w == 0 || h == 0 {
            return;
        }
        if self.fire.size() != (w, h) {
            self.fire = Fire::new(w, h, self.seed);
            if !self.style.animated {
                // Static frame: burn the fire up to a settled flame once, then never step again.
                for _ in 0..STATIC_WARMUP {
                    self.fire.step();
                }
            }
        }
        let style = self.style;
        let bg = style
            .color
            .has_color()
            .then(|| paint_color(style.color, 16));
        let mark = pick_mark(w, h);
        for y in 0..h {
            for x in 0..w {
                let heat = self.fire.at(x, y);
                let k = usize::from(heat) * GLYPHS.len() / 64;
                let k = k.min(GLYPHS.len() - 1);
                let mut utf8 = [0u8; 4];
                let (sym, fg): (&str, Option<(u8, u8, u8)>) = match mark
                    .as_ref()
                    .and_then(|m| m.cell(x, y, style.ascii_mark, &mut utf8))
                {
                    Some(sym) => (sym, Some(if k < 8 { MARK_COOL } else { MARK_HOT })),
                    None => (GLYPHS[k], None),
                };
                let Some(cell) = buf.cell_mut((area.x + x as u16, area.y + y as u16)) else {
                    continue;
                };
                cell.reset();
                cell.set_symbol(sym);
                if style.color.has_color() {
                    let fg = match fg {
                        Some(rgb) => rgb_color(style.color, rgb),
                        None => paint_color(style.color, RAMP[k]),
                    };
                    cell.set_fg(fg);
                    if let Some(bg) = bg {
                        cell.set_bg(bg);
                    }
                }
            }
        }
        // Label on the bottom row, centred.
        let label_w = LABEL.chars().count();
        if w >= label_w {
            let lx = (w - label_w) / 2;
            let y = area.y + (h - 1) as u16;
            for (i, ch) in LABEL.chars().enumerate() {
                let Some(cell) = buf.cell_mut((area.x + (lx + i) as u16, y)) else {
                    continue;
                };
                let mut utf8 = [0u8; 4];
                cell.reset();
                cell.set_symbol(ch.encode_utf8(&mut utf8));
                if style.color.has_color() {
                    cell.set_fg(paint_color(style.color, LABEL_GREY));
                    if let Some(bg) = bg {
                        cell.set_bg(bg);
                    }
                }
            }
        }
    }
}

/// The mark chosen for a terminal size, with its placement.
#[derive(Clone)]
struct PlacedMark {
    rows: Vec<&'static str>,
    x: usize,
    y: usize,
    cols: usize,
}

impl PlacedMark {
    /// The glyph at screen cell `(x, y)` if the mark has a dot there.
    fn cell<'a>(&self, x: usize, y: usize, ascii: bool, utf8: &'a mut [u8; 4]) -> Option<&'a str> {
        if x < self.x || y < self.y || x >= self.x + self.cols {
            return None;
        }
        let row = self.rows.get(y - self.y)?;
        let ch = row.chars().nth(x - self.x)?;
        if ch == '\u{2800}' {
            return None;
        }
        Some(if ascii {
            "#"
        } else {
            ch.encode_utf8(utf8) as &str
        })
    }
}

/// The largest in-tree Wind mask (shared with the welcome screen) that fits with a margin, else none.
/// Centred horizontally and a little above the middle.
fn pick_mark(w: usize, h: usize) -> Option<PlacedMark> {
    let &(cols, rows, mask) = crate::views::welcome::wind_mark_data::MASKS
        .iter()
        .rev()
        .find(|(c, r, _)| usize::from(*c) + 8 <= w && usize::from(*r) * 3 / 2 + 2 <= h)?;
    let (cols, rows) = (usize::from(cols), usize::from(rows));
    Some(PlacedMark {
        rows: mask.lines().collect(),
        x: (w - cols) / 2,
        y: (h / 2).saturating_sub(rows / 2 + 3).max(1),
        cols,
    })
}

/// A colour from the 256-colour ember ramp at the terminal's depth (truecolor gets the exact RGB equivalent).
fn paint_color(level: ColorLevel, idx: u8) -> Color {
    if level.has_truecolor() {
        let (r, g, b) = crate::render::color::indexed_to_rgb(idx);
        Color::Rgb(r, g, b)
    } else if level.has_256() {
        Color::Indexed(idx)
    } else {
        // 16-colour terminals: red, yellow, white bands.
        match idx {
            16 => Color::Black,
            52..=160 => Color::Red,
            196..=214 => Color::LightRed,
            220..=226 => Color::Yellow,
            245 => Color::DarkGray,
            _ => Color::White,
        }
    }
}

fn rgb_color(level: ColorLevel, (r, g, b): (u8, u8, u8)) -> Color {
    if level.has_truecolor() {
        Color::Rgb(r, g, b)
    } else if level.has_256() {
        Color::Indexed(if b < 255 { 230 } else { 231 })
    } else {
        Color::White
    }
}

#[cfg(test)]
mod tests;
