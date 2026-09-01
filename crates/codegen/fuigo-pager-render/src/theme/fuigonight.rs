//! FuigoNight theme: the Hearth palette -- an ember accent family on a
//! near-black canvas, matching Wayland's forge scheme.
//!
//! The canonical palette is defined in RGB (`Color::Rgb`).
//! At startup [`Theme::quantized`] downgrades every color to the terminal's detected capability level (256-color, 16-color, etc.).

use ratatui::style::{Color, Modifier};

use super::tokyonight::Theme;

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb(r, g, b)
}

// Backgrounds and text keep the inherited neutral grayscale ramp, which already
// suits Hearth. Only the ACCENT family moves: TokyoNight's cool blue/magenta out,
// the forge ember ramp in.
//
// Anchored at:
//   • bg  = #0d0d0d  (Hearth canvas)
//   • fg  = #e1e1e1
//
// Two constraints bound any edit here, both enforced by tests in `theme/mod.rs`:
//   1. Every background field must still quantize to Color::Black at
//      ColorLevel::Basic (`ansi16_quantize_without_override_collapses_*`).
//   2. `scrollbar_fg` must stay >= 30 summed-RGB units lighter than
//      `scrollbar_bg` (`scrollbar_thumb_contrasts_with_track_in_all_themes`).
//      Currently #111111 -> #242424, a margin of 57.
#[allow(dead_code)]
mod palette {
    use super::*;

    // ── Backgrounds ─────────────────────────────────────────────────────
    pub const BG: Color = rgb(10, 10, 10); //  #0a0a0a, Night (terminal bg)
    pub const BG_DARK: Color = rgb(12, 12, 12); //  #0c0c0c, darkest
    pub const BG_STORM_DARK: Color = rgb(17, 17, 17); //  #111111, dark bg
    pub const BG_STORM: Color = rgb(13, 13, 13); //  #0d0d0d, main bg (Hearth canvas)
    pub const BG_HIGHLIGHT: Color = rgb(36, 36, 36); //  #242424, highlight bg

    // ── Text / grays ────────────────────────────────────────────────────
    pub const FG: Color = rgb(225, 225, 225); // #e1e1e1, primary text
    pub const FG_DARK: Color = rgb(200, 200, 200); // #c8c8c8, secondary text
    pub const FG_GUTTER: Color = rgb(65, 65, 65); //  #414141, dim
    pub const COMMENT: Color = rgb(108, 108, 108); //  #6c6c6c, muted
    pub const DARK3: Color = rgb(90, 90, 90); //  #5a5a5a, medium gray
    pub const DARK5: Color = rgb(120, 120, 120); // #787878, bright gray

    // ── Hearth ember ramp ───────────────────────────────────────────────
    // EMBER is the brand accent and drives the prompt arrow, the focused
    // border and -- via OSC 12 -- the terminal cursor itself.
    pub const EMBER: Color = rgb(255, 107, 53); // #ff6b35, forge orange
    pub const EMBER_BRIGHT: Color = rgb(255, 140, 90); // #ff8c5a, lifted ember
    pub const EMBER_DEEP: Color = rgb(138, 69, 38); // #8a4526, banked coal
    pub const AMBER: Color = rgb(255, 169, 77); // #ffa94d
    pub const GOLD: Color = rgb(255, 209, 102); // #ffd166
    pub const SAND: Color = rgb(240, 168, 120); // #f0a878, file paths

    // ── Inherited accents kept for semantics ────────────────────────────
    // Red/green/yellow stay conventional: error, success and warning must not
    // be re-hued into the brand family or they stop reading as status.
    // Violet survives as the single cool accent, because `accent_verify` exists
    // specifically to be distinguishable from the gold of plan mode.
    pub const BLUE: Color = rgb(122, 162, 247); // #7aa2f7
    pub const BLUE0: Color = rgb(61, 89, 161); // #3d59a1
    pub const BLUE1: Color = rgb(58, 149, 171); // #3A95AB
    pub const CYAN: Color = rgb(125, 207, 255); // #7dcfff
    pub const GREEN: Color = rgb(158, 206, 106); // #9ece6a
    pub const GREEN1: Color = rgb(115, 218, 202); // #73daca
    pub const MAGENTA: Color = rgb(187, 154, 247); // #bb9af7
    pub const ORANGE: Color = rgb(255, 158, 100); // #ff9e64
    pub const PURPLE: Color = rgb(157, 124, 216); // #9d7cd8
    pub const RED: Color = rgb(247, 118, 142); // #f7768e
    pub const RED1: Color = rgb(219, 75, 75); // #db4b4b
    pub const TEAL: Color = rgb(26, 188, 156); // #1abc9c
    pub const YELLOW: Color = rgb(224, 175, 104); // #e0af68

    pub const RED_DARK: Color = rgb(66, 14, 20); // #420e14, quantizes to 256-color red, not gray
    pub const GREEN_DARK: Color = rgb(6, 56, 6); // #063806, quantizes to 256-color green, not gray
}
use palette::*;

impl Theme {
    pub const fn fuigonight() -> Self {
        Self {
            bg_base: BG_STORM,
            bg_light: BG_HIGHLIGHT,
            bg_dark: rgb(28, 28, 28), // lighter than bg_base for visible code blocks
            bg_highlight: BG_HIGHLIGHT,
            bg_hover: rgb(44, 44, 44),
            bg_terminal: BG,

            // EMBER here also colours the terminal cursor: `apply_cursor_color`
            // emits OSC 12 from `accent_user`.
            accent_user: EMBER,
            accent_assistant: EMBER_BRIGHT,
            accent_thinking: AMBER,
            accent_tool: DARK5,
            accent_system: AMBER,
            accent_error: RED,
            accent_success: GREEN,
            accent_running: EMBER_BRIGHT,
            accent_skill: GOLD,

            text_primary: FG,
            text_secondary: FG_DARK,

            gray_dim: rgb(88, 88, 88), // #585858, slightly brighter than FG_GUTTER
            gray: COMMENT,
            gray_bright: DARK5,

            command: YELLOW,
            // SAND rather than the inherited ORANGE (#ff9e64), which now sits
            // too close to EMBER_BRIGHT to tell a path from an accent.
            path: SAND,
            running: EMBER_BRIGHT,
            warning: YELLOW,

            fuzzy_accent: EMBER,

            accent_plan: rgb(255, 219, 141), // #FFDB8D, golden

            accent_verify: rgb(187, 154, 247), // #bb9af7, violet

            accent_remember: Color::Rgb(139, 195, 74), // #8BC34A, Material Design light green

            selection_border: rgb(60, 60, 60),
            prompt_border: rgb(48, 48, 48), // #303030, dimmer prompt chrome
            // Focus reads as the prompt warming up rather than merely brightening.
            prompt_border_active: EMBER_DEEP,
            hover_border: rgb(30, 30, 30),

            accent_model: GOLD,

            scrollbar_bg: BG_STORM_DARK,
            scrollbar_fg: BG_HIGHLIGHT,

            diff_delete_bg: RED_DARK,
            diff_delete_fg: RED,
            diff_insert_bg: GREEN_DARK,
            diff_insert_fg: GREEN,
            diff_equal_fg: COMMENT,
            diff_gutter_fg: COMMENT,

            bg_visual: rgb(54, 54, 54),

            paste_bg: BG_STORM_DARK,
            paste_fg: FG_DARK,
            paste_dim: FG_GUTTER,

            md_heading_h1: EMBER,
            md_heading_h1_mod: Modifier::BOLD,
            md_heading_h2: AMBER,
            md_heading_h2_mod: Modifier::BOLD,
            md_heading_h3: GOLD,
            md_heading_h3_mod: Modifier::BOLD,
            md_heading_h4: DARK5, // bright gray
            md_heading_h4_mod: Modifier::BOLD,
            md_heading_h5: COMMENT, // medium gray
            md_heading_h5_mod: Modifier::BOLD,
            md_heading_h6: DARK3, // medium gray, unbold
            md_heading_h6_mod: Modifier::empty(),
            md_code: SAND,
            md_task_checked: GREEN,
            md_task_unchecked: FG_DARK, // text_secondary
            md_muted: COMMENT,
            md_code_bg: rgb(28, 28, 28),
            md_text: FG_DARK,
            link_fg: AMBER, // warm, and still clearly not body text
        }
    }
}
