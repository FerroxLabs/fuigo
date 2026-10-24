use std::collections::BTreeSet;
use std::f32::consts::{FRAC_PI_2, PI};

use ratatui::style::Style;

use super::*;
use crate::views::welcome::wind_spin::Pose;

const DARK_BG: Color = Color::Rgb(30, 32, 38);
const DARK_FG: Color = Color::Rgb(220, 224, 230);
const LIGHT_BG: Color = Color::Rgb(250, 248, 244);
const LIGHT_FG: Color = Color::Rgb(40, 42, 48);

fn spec(bg: Color, fg: Color, pose: Pose) -> MarkSpec {
    MarkSpec {
        bg,
        fg,
        level: ColorLevel::TrueColor,
        pose,
    }
}

fn rest(bg: Color, fg: Color) -> MarkSpec {
    spec(bg, fg, Pose::REST)
}

fn at_theta(theta: f32) -> MarkSpec {
    spec(DARK_BG, DARK_FG, Pose { theta, gust: None })
}

const W: u16 = 120;
const H: u16 = 40;
fn screen() -> Rect {
    Rect::new(0, 0, W, H)
}
fn region() -> Rect {
    Rect::new(0, 3, W, H - 4)
}

fn render(w: u16, h: u16, s: &MarkSpec) -> (Buffer, bool) {
    let area = Rect::new(0, 0, w, h);
    let mut buf = Buffer::empty(area);
    buf.set_style(area, Style::default().bg(s.bg));
    let drew = paint(&mut buf, area, Rect::new(0, 3, w, h - 4), s);
    (buf, drew)
}

fn braille_cells(buf: &Buffer) -> Vec<(u16, u16, Color)> {
    let a = *buf.area();
    let mut v = Vec::new();
    for y in a.y..a.bottom() {
        for x in a.x..a.right() {
            let c = &buf[(x, y)];
            if c.symbol()
                .chars()
                .next()
                .is_some_and(|ch| ('\u{2801}'..='\u{28FF}').contains(&ch))
            {
                v.push((x, y, c.fg));
            }
        }
    }
    v
}

fn rgb(c: Color) -> (u8, u8, u8) {
    resolve_to_rgb(c).unwrap()
}

/// The mask picked for 120x40, its dot grid and where the mark sits on screen.
fn mark_geometry() -> (usize, usize, Vec<bool>, u16, u16) {
    let &(cols, rows, mask) = pick_size(screen(), region()).unwrap();
    let (c, r) = (cols as usize, rows as usize);
    let ox = region().x + (region().width - cols) / 2;
    let oy = region().y + (region().height - rows) / 2;
    (c, r, decode(mask, c, r), ox, oy)
}

/// Every lit dot on screen, as `(x, y)` in mask dot coordinates.
fn lit_dots(buf: &Buffer) -> BTreeSet<(usize, usize)> {
    let (cols, rows, _, ox, oy) = mark_geometry();
    let mut set = BTreeSet::new();
    for cr in 0..rows {
        for cc in 0..cols {
            let sym = buf[(ox + cc as u16, oy + cr as u16)]
                .symbol()
                .chars()
                .next()
                .unwrap_or(' ');
            let v = (sym as u32).wrapping_sub(0x2800);
            if v == 0 || v >= 0x100 {
                continue;
            }
            for (dy, row) in BITS.iter().enumerate() {
                for (dx, bit) in row.iter().enumerate() {
                    if v as u8 & bit != 0 {
                        set.insert((cc * 2 + dx, cr * 4 + dy));
                    }
                }
            }
        }
    }
    set
}

fn mask_dots() -> BTreeSet<(usize, usize)> {
    let (cols, rows, dots, ..) = mark_geometry();
    let w = cols * 2;
    (0..rows * 4)
        .flat_map(|y| (0..w).map(move |x| (x, y)))
        .filter(|&(x, y)| dots[y * w + x])
        .collect()
}

#[test]
fn shown_on_empty_120x40() {
    let (buf, drew) = render(120, 40, &rest(DARK_BG, DARK_FG));
    assert!(drew);
    assert!(braille_cells(&buf).len() > 300);
}

#[test]
fn picks_largest_size_that_fits_with_margin() {
    let s = Rect::new(0, 0, 120, 40);
    assert_eq!(
        pick_size(s, Rect::new(0, 3, 120, 36)).map(|m| m.0),
        Some(60)
    );
    let s = Rect::new(0, 0, 70, 24);
    assert_eq!(pick_size(s, Rect::new(0, 3, 70, 20)).map(|m| m.0), Some(32));
}

#[test]
fn hidden_when_terminal_is_small() {
    let (buf, drew) = render(60, 20, &rest(DARK_BG, DARK_FG));
    assert!(!drew);
    assert!(braille_cells(&buf).is_empty());
    assert!(!render(69, 40, &rest(DARK_BG, DARK_FG)).1);
    assert!(!render(120, 23, &rest(DARK_BG, DARK_FG)).1);
    assert!(render(70, 24, &rest(DARK_BG, DARK_FG)).1);
}

#[test]
fn hidden_without_colour() {
    let mut s = rest(DARK_BG, DARK_FG);
    s.level = ColorLevel::None;
    let (buf, drew) = render(120, 40, &s);
    assert!(!drew);
    assert!(braille_cells(&buf).is_empty());
}

#[test]
fn rest_frame_is_deterministic() {
    let a = render(120, 40, &rest(DARK_BG, DARK_FG)).0;
    let b = render(120, 40, &rest(DARK_BG, DARK_FG)).0;
    assert_eq!(a, b);
}

// The old halftone lit every other dot, which left uneven gaps between cells
#[test]
fn rest_frame_is_solid_every_mask_dot_is_lit_and_nothing_else() {
    for (bg, fg) in [(DARK_BG, DARK_FG), (LIGHT_BG, LIGHT_FG)] {
        let (buf, _) = render(120, 40, &rest(bg, fg));
        let lit = lit_dots(&buf);
        let mask = mask_dots();
        assert!(mask.len() > 1000, "mask has {} dots", mask.len());
        let missing: Vec<_> = mask.difference(&lit).take(5).collect();
        let extra: Vec<_> = lit.difference(&mask).take(5).collect();
        assert!(
            missing.is_empty(),
            "mask dots left unlit (checkerboard?): {missing:?}"
        );
        assert!(
            extra.is_empty(),
            "dots lit outside the mask (shadow at rest?): {extra:?}"
        );
    }
}

#[test]
fn the_mask_itself_is_solid_strokes_without_pinholes() {
    // Inside the shape no dot is isolated: every lit dot has a lit neighbour
    let (cols, rows, dots, ..) = mark_geometry();
    let w = cols * 2;
    let h = rows * 4;
    for y in 0..h {
        for x in 0..w {
            if !dots[y * w + x] {
                continue;
            }
            let near = [(0i32, 1i32), (1, 0), (0, -1), (-1, 0)]
                .iter()
                .any(|(dx, dy)| {
                    let (nx, ny) = (x as i32 + dx, y as i32 + dy);
                    nx >= 0
                        && ny >= 0
                        && (nx as usize) < w
                        && (ny as usize) < h
                        && dots[ny as usize * w + nx as usize]
                });
            assert!(near, "isolated dot at ({x},{y})");
        }
    }
}

#[test]
fn no_depth_layers_at_rest() {
    let (cols, rows, dots, ..) = mark_geometry();
    let comp = compose(&dots, cols, rows, 0.0);
    assert!(comp.back.iter().all(|&b| b == 0));
}

#[test]
fn face_and_depth_layers_never_share_a_cell() {
    let (cols, rows, dots, ..) = mark_geometry();
    for deg in [
        10.0f32, 35.0, 60.0, 90.0, 120.0, 150.0, 200.0, 250.0, 300.0, 340.0,
    ] {
        let comp = compose(&dots, cols, rows, deg.to_radians());
        for i in 0..cols * rows {
            assert!(
                comp.face[i] == 0 || comp.back[i] == 0,
                "{deg} deg: cell {i} holds both face and depth dots"
            );
        }
    }
}

#[test]
fn frame_at_ninety_degrees_is_narrow_and_the_depth_layers_show() {
    let (buf, _) = render(120, 40, &at_theta(FRAC_PI_2));
    let cells = braille_cells(&buf);
    let lo = cells.iter().map(|c| c.0).min().unwrap();
    let hi = cells.iter().map(|c| c.0).max().unwrap();
    assert!(hi - lo < 8, "edge-on mark spans {} cells", hi - lo + 1);
    let shadow = shadow_color(&at_theta(FRAC_PI_2)).unwrap();
    assert!(
        cells.iter().any(|c| c.2 == shadow),
        "no depth-layer cells at 90 degrees"
    );
}

#[test]
fn frame_at_zero_is_full_width_and_at_180_is_its_mirror() {
    let (front, _) = render(120, 40, &at_theta(0.0));
    let (back, _) = render(120, 40, &at_theta(PI));
    let (cols, ..) = mark_geometry();
    let w = cols * 2;
    let cells = braille_cells(&front);
    let span =
        cells.iter().map(|c| c.0).max().unwrap() - cells.iter().map(|c| c.0).min().unwrap() + 1;
    assert!(
        span as usize >= cols - 2,
        "rest frame spans {span} of {cols} cells"
    );
    // Facing away shows the same art mirrored left to right
    let mirrored: BTreeSet<(usize, usize)> = lit_dots(&front)
        .iter()
        .map(|&(x, y)| (w - 1 - x, y))
        .collect();
    assert_eq!(lit_dots(&back), mirrored);
}

#[test]
fn edge_on_face_is_dimmer_than_at_rest() {
    // Quarter turn away from the light: |cos| = 0 halves the foreground mix and there is no ember to add back
    let rest_c = face_color(&at_theta(0.0), 0.5, 0.5).unwrap();
    let edge_c = face_color(&at_theta(3.0 * FRAC_PI_2), 0.5, 0.5).unwrap();
    assert!(
        rgb(edge_c).1 < rgb(rest_c).1,
        "{:?} vs {:?}",
        rgb(edge_c),
        rgb(rest_c)
    );
}

fn luminance(c: Color) -> f32 {
    let (r, g, b) = rgb(c);
    0.2126 * f32::from(r) + 0.7152 * f32::from(g) + 0.0722 * f32::from(b)
}

#[test]
fn spin_never_brightens_the_mark_beyond_its_rested_look() {
    let rest_max = braille_cells(&render(120, 40, &rest(DARK_BG, DARK_FG)).0)
        .iter()
        .map(|c| luminance(c.2))
        .fold(0.0, f32::max);
    // The rested far-right edge is the brightest (it carries the most ember); turning must not exceed it by more than the ember tint (at most 10 luminance)
    for deg in (0..360).step_by(15) {
        let s = spec(
            DARK_BG,
            DARK_FG,
            Pose {
                theta: (deg as f32).to_radians(),
                gust: None,
            },
        );
        for (_, _, c) in braille_cells(&render(120, 40, &s).0) {
            if c == shadow_color(&s).unwrap() {
                continue;
            }
            assert!(
                luminance(c) <= rest_max + 10.0,
                "{deg} deg: {} vs rest max {rest_max}",
                luminance(c)
            );
        }
        // The gust is the one deliberate flash: faint, at most its peak mix toward ember
        let g = spec(
            DARK_BG,
            DARK_FG,
            Pose {
                theta: (deg as f32).to_radians(),
                gust: Some(0.5),
            },
        );
        for (_, _, c) in braille_cells(&render(120, 40, &g).0) {
            assert!(
                luminance(c) <= rest_max + 18.0,
                "{deg} deg gust: {}",
                luminance(c)
            );
        }
    }
    // And the rested look itself is faint: nothing near the foreground
    assert!(rest_max < luminance(DARK_FG) * 0.5, "rest max {rest_max}");
}

#[test]
fn ember_tint_follows_sin_and_is_absent_when_facing_away() {
    let turning = face_color(&at_theta(FRAC_PI_2), 0.5, 0.2).unwrap();
    let away = face_color(&at_theta(3.0 * FRAC_PI_2), 0.5, 0.2).unwrap();
    let warmth = |c: Color| {
        let (r, _, b) = rgb(c);
        i32::from(r) - i32::from(b)
    };
    assert!(
        warmth(turning) > warmth(away) + 5,
        "{} vs {}",
        warmth(turning),
        warmth(away)
    );
}

#[test]
fn right_edge_dots_are_warmer_than_left_edge_dots() {
    for (bg, fg) in [(DARK_BG, DARK_FG), (LIGHT_BG, LIGHT_FG)] {
        let (buf, _) = render(120, 40, &rest(bg, fg));
        let cells = braille_cells(&buf);
        let lo = cells.iter().map(|c| c.0).min().unwrap();
        let hi = cells.iter().map(|c| c.0).max().unwrap();
        let warmth = |x: u16| {
            let v: Vec<i32> = cells
                .iter()
                .filter(|c| c.0 == x)
                .map(|c| {
                    let (r, _, b) = rgb(c.2);
                    i32::from(r) - i32::from(b)
                })
                .collect();
            v.iter().sum::<i32>() / v.len() as i32
        };
        assert!(
            warmth(hi) > warmth(lo) + 15,
            "right {} vs left {}",
            warmth(hi),
            warmth(lo)
        );
    }
}

#[test]
fn face_is_lit_from_the_top() {
    let (buf, _) = render(120, 40, &rest(DARK_BG, DARK_FG));
    let cells = braille_cells(&buf);
    let top = cells.iter().map(|c| c.1).min().unwrap();
    let bottom = cells.iter().map(|c| c.1).max().unwrap();
    let green = |y: u16| {
        cells
            .iter()
            .filter(|c| c.1 == y)
            .map(|c| u32::from(rgb(c.2).1))
            .max()
            .unwrap()
    };
    assert!(
        green(top) > green(bottom),
        "{} vs {}",
        green(top),
        green(bottom)
    );
}

#[test]
fn light_theme_is_darker_than_the_background_with_a_darker_ember() {
    let (buf, _) = render(120, 40, &rest(LIGHT_BG, LIGHT_FG));
    let bg = rgb(LIGHT_BG);
    for (_, _, c) in braille_cells(&buf) {
        let (r, g, b) = rgb(c);
        assert!(
            r <= bg.0 && g < bg.1 && b < bg.2,
            "{:?} must be darker than the background",
            (r, g, b)
        );
        // Faint: no more than ~45% of the way to black
        assert!(f32::from(g) > f32::from(bg.1) * 0.55, "too strong: {g}");
    }
    let dark_ember = rgb(ember_color(LIGHT_BG).unwrap());
    let brand = rgb(EMBER);
    assert!(
        dark_ember.0 < brand.0 && dark_ember.1 < brand.1,
        "{dark_ember:?}"
    );
    assert_eq!(ember_color(DARK_BG), Some(EMBER));
}

#[test]
fn gust_mid_sweep_tints_cells_and_the_settled_frame_has_none() {
    let settled = render(120, 40, &rest(DARK_BG, DARK_FG)).0;
    let mid = render(
        120,
        40,
        &spec(
            DARK_BG,
            DARK_FG,
            Pose {
                theta: 0.0,
                gust: Some(0.5),
            },
        ),
    )
    .0;
    let warmer = braille_cells(&mid)
        .iter()
        .filter(|(x, y, c)| {
            let (r, _, b) = rgb(*c);
            let (r0, _, b0) = rgb(settled[(*x, *y)].fg);
            i32::from(r) - i32::from(b) > i32::from(r0) - i32::from(b0) + 4
        })
        .count();
    assert!(
        warmer > 10,
        "ember-tinted cells at the middle of the gust: {warmer}"
    );
    // Only a band is tinted: the far-left cell is untouched
    let cells = braille_cells(&settled);
    let leftmost = cells.iter().min_by_key(|c| c.0).unwrap();
    assert_eq!(
        mid[(leftmost.0, leftmost.1)].fg,
        settled[(leftmost.0, leftmost.1)].fg
    );
    // Gust at t=0 is parked off the left edge
    let first = render(
        120,
        40,
        &spec(
            DARK_BG,
            DARK_FG,
            Pose {
                theta: 0.0,
                gust: Some(0.0),
            },
        ),
    )
    .0;
    assert_eq!(first, settled);
}

#[test]
fn ansi_colours_fall_back_to_dim_grey_without_depth_layers() {
    let mut s = spec(
        Color::Black,
        Color::White,
        Pose {
            theta: 1.0,
            gust: None,
        },
    );
    s.level = ColorLevel::Basic;
    let (buf, drew) = render(120, 40, &s);
    assert!(drew);
    assert!(braille_cells(&buf).iter().all(|c| c.2 == Color::DarkGray));
}

#[test]
fn text_painted_afterwards_survives_and_bg_is_preserved() {
    let s = rest(DARK_BG, DARK_FG);
    let area = Rect::new(0, 0, 120, 40);
    let mut buf = Buffer::empty(area);
    buf.set_style(area, Style::default().bg(DARK_BG));
    paint(&mut buf, area, Rect::new(0, 3, 120, 36), &s);
    let text = "Ask Fuigo to do anything";
    buf.set_string(40, 20, text, Style::default().fg(DARK_FG));
    let row: String = (40..40 + text.len() as u16)
        .map(|x| buf[(x, 20)].symbol().to_string())
        .collect();
    assert_eq!(row, text);
    assert!(
        braille_cells(&buf)
            .iter()
            .all(|(x, y, _)| buf[(*x, *y)].bg == DARK_BG)
    );
}
