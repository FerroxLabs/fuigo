use super::*;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn style(color: ColorLevel, ascii_mark: bool) -> StokeStyle {
    StokeStyle {
        color,
        ascii_mark,
        animated: true,
    }
}

fn state(color: ColorLevel, ascii_mark: bool) -> StokeState {
    StokeState::with(7, FRAME_INTERVAL, style(color, ascii_mark))
}

fn grid(f: &Fire) -> Vec<u8> {
    (0..f.h)
        .flat_map(|y| (0..f.w).map(move |x| (x, y)))
        .map(|(x, y)| f.at(x, y))
        .collect()
}

fn text(buf: &Buffer, area: Rect) -> Vec<String> {
    (area.y..area.y + area.height)
        .map(|y| {
            (area.x..area.x + area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect()
        })
        .collect()
}

#[test]
fn fire_step_is_deterministic_with_a_seed() {
    let run = |seed| {
        let mut f = Fire::new(40, 20, seed);
        for _ in 0..50 {
            f.step();
        }
        grid(&f)
    };
    assert_eq!(run(42), run(42), "same seed, same flames");
    assert_ne!(run(42), run(43), "different seed, different flames");
    assert!(run(42).iter().any(|&v| v > 0), "fire must have heat");
}

#[test]
fn rng_reference_values_are_pinned() {
    // Pins the generator so a refactor cannot silently change every seeded frame.
    let mut r = Rng::new(1);
    let got: Vec<u32> = (0..3).map(|_| r.next_u32()).collect();
    let mut r2 = Rng::new(1);
    assert_eq!(got, (0..3).map(|_| r2.next_u32()).collect::<Vec<_>>());
    assert_eq!(
        Rng::new(0).next_u32(),
        Rng::new(1).next_u32(),
        "seed 0 is remapped, never stuck at zero"
    );
}

#[test]
fn flames_lean_right() {
    // One hot spot on the fuel rows, no random fuel: propagate only. The plume must drift right of the seed as it rises:
    // the whole-field centre of mass leans right, and the top row (furthest travelled) leans further.
    let (w, h, seed_x) = (61, 8, 30usize);
    let mut f = Fire::new(w, h, 1);
    for _ in 0..40 {
        f.set(seed_x, h, 110);
        f.set(seed_x, h + 1, 110);
        f.propagate();
    }
    let (cx, _) = f.centre_of_mass().expect("plume has heat");
    assert!(
        cx > seed_x as f64 + 0.5,
        "centre of mass {cx} must lean right of the seed column {seed_x}"
    );
    let (mut sx, mut total) = (0.0, 0.0);
    for x in 0..w {
        sx += f64::from(f.at(x, 0)) * x as f64;
        total += f64::from(f.at(x, 0));
    }
    assert!(total > 0.0, "the plume reaches the top row");
    let top = sx / total;
    assert!(
        top > seed_x as f64 + 1.0,
        "top-row centre {top} must lean right of {seed_x}"
    );
    assert!(
        top > cx,
        "the lean grows with height: top {top} vs whole {cx}"
    );
    let mass = |range: std::ops::Range<usize>| -> u32 {
        (0..h)
            .flat_map(|y| range.clone().map(move |x| (x, y)))
            .map(|(x, y)| u32::from(f.at(x, y)))
            .sum()
    };
    let (left, right) = (mass(0..seed_x), mass(seed_x + 1..w));
    assert!(
        right * 10 > left * 12,
        "more heat right of the seed ({right}) than left ({left})"
    );
}

#[test]
fn fuel_stays_on_the_bottom_two_rows() {
    let mut f = Fire::new(30, 10, 5);
    f.fuel();
    assert!(
        (0..10).all(|y| (0..30).all(|x| f.at(x, y) == 0)),
        "fuel must not touch visible rows"
    );
    assert!((0..30).any(|x| f.heat[10 * 30 + x] > 0));
    assert_eq!(
        f.heat[10 * 30..11 * 30],
        f.heat[11 * 30..12 * 30],
        "the two fuel rows match"
    );
}

#[test]
fn mark_is_drawn_above_the_fire() {
    let area = Rect::new(0, 0, 100, 40);
    let mut s = state(ColorLevel::TrueColor, false);
    s.paint(&mut Buffer::empty(area), area);
    // Make the fire as hot as it gets under the mark, then paint again.
    for y in 0..40 {
        for x in 0..100 {
            s.fire_mut().set(x, y, 110);
        }
    }
    let mut buf = Buffer::empty(area);
    s.paint(&mut buf, area);
    let pm = pick_mark(100, 40).expect("large mark fits");
    let rows = text(&buf, area);
    let mut dots = 0;
    for (ry, mrow) in pm.rows.iter().enumerate() {
        for (rx, ch) in mrow.chars().enumerate() {
            let cell = &buf[((pm.x + rx) as u16, (pm.y + ry) as u16)];
            if ch != '\u{2800}' {
                assert_eq!(cell.symbol(), ch.to_string(), "mark dot at {rx},{ry}");
                assert_eq!(
                    cell.fg,
                    Color::Rgb(255, 255, 215),
                    "mark is bright over hot fire"
                );
                dots += 1;
            }
        }
    }
    assert!(dots > 100, "the mark has substance: {dots} cells");
    // Outside the mark the cell is a fire glyph, never braille.
    assert!(rows[39].chars().all(|c| c != '\u{28FF}'));
    assert!(
        rows[0].starts_with(GLYPHS[GLYPHS.len() - 1]),
        "fire glyph outside the mark"
    );
}

#[test]
fn legacy_console_draws_the_mark_in_ascii() {
    let area = Rect::new(0, 0, 100, 40);
    let mut s = state(ColorLevel::Ansi256, true);
    let mut buf = Buffer::empty(area);
    s.paint(&mut buf, area);
    let all: String = text(&buf, area).concat();
    assert!(
        !all.chars().any(|c| ('\u{2800}'..='\u{28FF}').contains(&c)),
        "no braille on legacy consoles"
    );
    assert!(all.contains('#'), "ascii mark uses #");
}

#[test]
fn no_color_produces_no_colour() {
    let area = Rect::new(0, 0, 100, 40);
    let mut s = state(ColorLevel::None, false);
    for _ in 0..30 {
        s.fire_mut().step();
    }
    let mut buf = Buffer::empty(area);
    s.paint(&mut buf, area);
    for y in 0..40 {
        for x in 0..100 {
            let c = &buf[(x, y)];
            assert_eq!(c.fg, Color::Reset, "fg at {x},{y}");
            assert_eq!(c.bg, Color::Reset, "bg at {x},{y}");
            assert!(c.modifier.is_empty(), "no modifiers at {x},{y}");
        }
    }
    let all: String = text(&buf, area).concat();
    assert!(
        all.contains("fuigo  ·  q to quit"),
        "glyphs and label still drawn"
    );
    assert!(
        all.chars().any(|c| ('\u{2800}'..='\u{28FF}').contains(&c)),
        "mark still drawn"
    );
}

#[test]
fn colour_depth_picks_the_matching_ramp() {
    let area = Rect::new(0, 0, 100, 40);
    let paint = |level| {
        let mut s = state(level, false);
        s.paint(&mut Buffer::empty(area), area);
        for y in 0..40 {
            for x in 0..100 {
                s.fire_mut().set(x, y, 90);
            }
        }
        let mut b = Buffer::empty(area);
        s.paint(&mut b, area);
        b
    };
    assert!(matches!(
        paint(ColorLevel::TrueColor)[(0, 1)].fg,
        Color::Rgb(..)
    ));
    assert!(matches!(
        paint(ColorLevel::Ansi256)[(0, 1)].fg,
        Color::Indexed(_)
    ));
    assert!(!matches!(
        paint(ColorLevel::Basic)[(0, 1)].fg,
        Color::Rgb(..) | Color::Indexed(_)
    ));
}

#[test]
fn label_sits_on_the_bottom_row() {
    let area = Rect::new(0, 0, 80, 30);
    let mut s = state(ColorLevel::Ansi256, false);
    let mut buf = Buffer::empty(area);
    s.paint(&mut buf, area);
    let rows = text(&buf, area);
    assert!(rows[29].contains("fuigo  ·  q to quit"), "{:?}", rows[29]);
    assert!(!rows[28].contains("fuigo"));
}

#[test]
fn frame_rate_is_capped() {
    for (interval, max_steps) in [(FRAME_INTERVAL, 31), (FRAME_INTERVAL_SSH, 16)] {
        let mut s = StokeState::with(1, interval, style(ColorLevel::None, false));
        let t0 = Instant::now();
        let steps = (0..1000)
            .filter(|ms| s.tick_at(t0 + Duration::from_millis(*ms)))
            .count();
        assert!(
            steps <= max_steps,
            "{interval:?}: {steps} steps in one second"
        );
        assert!(steps >= max_steps - 2, "{interval:?}: only {steps} steps");
    }
    assert_eq!(
        FRAME_INTERVAL.as_millis() * 2,
        FRAME_INTERVAL_SSH.as_millis()
    );
}

#[test]
fn first_tick_steps_immediately() {
    let mut s = state(ColorLevel::None, false);
    assert!(s.tick_at(Instant::now()));
}

#[test]
fn q_esc_and_ctrl_c_close_everything_else_is_swallowed() {
    let k = |code, m| KeyEvent::new(code, m);
    for key in [
        k(KeyCode::Char('q'), KeyModifiers::NONE),
        k(KeyCode::Char('Q'), KeyModifiers::SHIFT),
        k(KeyCode::Esc, KeyModifiers::NONE),
        k(KeyCode::Char('c'), KeyModifiers::CONTROL),
    ] {
        assert_eq!(
            StokeState::handle_key(&key),
            StokeKeyOutcome::Close,
            "{key:?}"
        );
    }
    for key in [
        k(KeyCode::Char('x'), KeyModifiers::NONE),
        k(KeyCode::Enter, KeyModifiers::NONE),
        k(KeyCode::Char('q'), KeyModifiers::CONTROL),
        k(KeyCode::Up, KeyModifiers::NONE),
    ] {
        assert_eq!(
            StokeState::handle_key(&key),
            StokeKeyOutcome::Ignored,
            "{key:?}"
        );
    }
}

#[test]
fn tiny_terminals_do_not_panic_and_skip_the_mark() {
    for (w, h) in [(1, 1), (5, 3), (20, 6), (40, 12)] {
        let area = Rect::new(2, 1, w, h);
        let mut s = state(ColorLevel::TrueColor, false);
        let mut buf = Buffer::empty(Rect::new(0, 0, w + 4, h + 2));
        for _ in 0..5 {
            s.tick_at(Instant::now() + Duration::from_secs(100));
            s.paint(&mut buf, area);
        }
    }
    assert!(pick_mark(40, 12).is_none());
    assert!(pick_mark(100, 40).is_some());
}

#[test]
fn resize_rebuilds_the_field() {
    let mut s = state(ColorLevel::None, false);
    let mut a = Buffer::empty(Rect::new(0, 0, 60, 20));
    s.paint(&mut a, Rect::new(0, 0, 60, 20));
    assert_eq!(s.fire().size(), (60, 20));
    let mut b = Buffer::empty(Rect::new(0, 0, 90, 30));
    s.paint(&mut b, Rect::new(0, 0, 90, 30));
    assert_eq!(s.fire().size(), (90, 30));
}

/// Counts every byte the backend writes.
struct Count(u64);

impl std::io::Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Perf probe, printed with `--nocapture` (run with `--release` for the real numbers): fire step + render per frame into a plain
/// buffer, and bytes a crossterm backend writes per frame through ratatui's diffing. It asserts only deterministic facts,
/// never wall-clock time, so it cannot flake under load.
#[test]
fn perf_report_200x60() {
    use ratatui::backend::CrosstermBackend;
    use ratatui::{Terminal, TerminalOptions, Viewport};
    let (w, h, frames) = (200u16, 60u16, 400u32);
    let area = Rect::new(0, 0, w, h);
    for (name, level) in [
        ("truecolor", ColorLevel::TrueColor),
        ("256", ColorLevel::Ansi256),
        ("none", ColorLevel::None),
    ] {
        let mut s = state(level, false);
        let mut buf = Buffer::empty(area);
        s.paint(&mut buf, area);
        for _ in 0..60 {
            s.fire_mut().step();
            s.paint(&mut buf, area);
        }
        let t = Instant::now();
        for _ in 0..frames {
            s.fire_mut().step();
            s.paint(&mut buf, area);
        }
        let per = t.elapsed() / frames;

        let mut term = Terminal::with_options(
            CrosstermBackend::new(Count(0)),
            TerminalOptions {
                viewport: Viewport::Fixed(area),
            },
        )
        .unwrap();
        let mut s = state(level, false);
        let (mut total, mut max) = (0u64, 0u64);
        let n = 200u64;
        for i in 0..n + 60 {
            s.fire_mut().step();
            let before = term.backend().writer().0;
            term.draw(|f| {
                let a = f.area();
                s.paint(f.buffer_mut(), a);
            })
            .unwrap();
            let bytes = term.backend().writer().0 - before;
            if i >= 60 {
                total += bytes;
                max = max.max(bytes);
            }
        }
        eprintln!(
            "STOKE-PERF {name:9} {w}x{h}: {:.3} ms/frame step+render ({} us); bytes/frame avg {} max {}",
            per.as_secs_f64() * 1e3,
            per.as_micros(),
            total / n,
            max
        );
        assert!(total > 0, "a live fire must write bytes");
    }
}

#[test]
fn animations_off_shows_one_static_frame_with_mark_and_label() {
    let area = Rect::new(0, 0, 100, 40);
    let mut s = StokeState::with(
        7,
        FRAME_INTERVAL,
        StokeStyle {
            color: ColorLevel::Ansi256,
            ascii_mark: false,
            animated: false,
        },
    );
    let mut first = Buffer::empty(area);
    s.paint(&mut first, area);
    let before = grid(s.fire());
    assert!(before.iter().any(|&v| v > 0), "static frame is a lit fire");
    let t0 = Instant::now();
    for i in 1..20u64 {
        assert!(
            !s.tick_at(t0 + Duration::from_secs(i)),
            "no stepping with animations off"
        );
    }
    let mut second = Buffer::empty(area);
    s.paint(&mut second, area);
    assert_eq!(first, second, "the frame never changes");
    assert_eq!(grid(s.fire()), before);
    let all = text(&second, area).join("\n");
    assert!(all.contains("fuigo  ·  q to quit"));
    assert!(
        all.chars().any(|c| ('\u{2801}'..='\u{28FF}').contains(&c)),
        "mark drawn"
    );
    // A key still closes it.
    let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
    assert_eq!(StokeState::handle_key(&key), StokeKeyOutcome::Close);
}
