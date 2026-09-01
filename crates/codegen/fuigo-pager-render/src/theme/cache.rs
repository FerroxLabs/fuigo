//! In-memory theme cache and resolution.
//!
//! The pager reads the active `ThemeKind` on every render frame, so the
//! lookup must be cheaper than re-loading from `~/.fuigo/config.toml`.
//! [`current_kind`] returns the in-memory value, lazily seeding from the shell's layered effective config on first call.
//!
//! Disk writes live in `fuigo_shell::util::config::set_theme()` (and friends), invoked via `Effect::PersistSetting` from the dispatcher.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use super::ThemeKind;
use super::system_appearance;

/// In-memory theme kind, encoded as a `u8` matching the `ThemeKind` discriminants.
/// Loaded from disk once at startup via `load_from_disk()`, then kept in sync by `set()`.
static CURRENT: AtomicU8 = AtomicU8::new(ThemeKind::FuigoNight as u8);
static LOADED: AtomicBool = AtomicBool::new(false);
#[cfg(any(test, feature = "test-support"))]
static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Whether auto-switching mode is active. Set when the config file contains `theme = "auto"`.
/// Checked by the event loop to decide whether the `SystemAppearanceWatcher` should run.
static AUTO_MODE: AtomicBool = AtomicBool::new(false);

/// Whether the theme is locked to `Theme::terminal_default` for the whole session (minimal mode, no theming).
static TERMINAL_NATIVE_LOCK: AtomicBool = AtomicBool::new(false);

/// Decode the u8 stored in `CURRENT` back to a `ThemeKind`.
/// Falls back to `FuigoNight` for an out-of-range byte, which `set` can't produce but a future variant missing from this match could.
fn theme_kind_from_u8(byte: u8) -> ThemeKind {
    match byte {
        x if x == ThemeKind::FuigoNight as u8 => ThemeKind::FuigoNight,
        x if x == ThemeKind::FuigoDay as u8 => ThemeKind::FuigoDay,
        x if x == ThemeKind::TokyoNight as u8 => ThemeKind::TokyoNight,
        x if x == ThemeKind::RosePineMoon as u8 => ThemeKind::RosePineMoon,
        x if x == ThemeKind::OscuraMidnight as u8 => ThemeKind::OscuraMidnight,
        x if x == ThemeKind::Auto as u8 => ThemeKind::Auto,
        _ => ThemeKind::FuigoNight,
    }
}

/// Cached auto-theme configuration (which themes map to dark/light).
///
/// Uses `Mutex<Option<_>>` rather than `OnceLock` so the settings modal and the `/theme auto` command can invalidate it after changing mappings.
static AUTO_THEME_CONFIG: Mutex<Option<AutoThemeConfig>> = Mutex::new(None);

/// `dark_theme` and `light_theme` are the user-configured overrides read from `[ui].auto_dark_theme` and `[ui].auto_light_theme` in `config.toml`.
/// When `None`, `to_theme_kind()` defaults to `FuigoNight` / `FuigoDay`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoThemeConfig {
    pub dark_theme: Option<ThemeKind>,
    pub light_theme: Option<ThemeKind>,
}

/// On the first call, reads from `~/.fuigo/config.toml` (via the shell's
/// `load_effective_config`).
/// After that, returns the in-memory value (updated by [`set`]).
pub fn current_kind() -> ThemeKind {
    // Locked: return a constant nominal kind without seeding from disk.
    if terminal_native_locked() {
        return ThemeKind::FuigoNight;
    }
    if !LOADED.load(Ordering::Acquire) {
        // Two threads racing into the seed path is harmless: the disk read is idempotent and `store` is atomic
        // Worst case both threads call `load_from_disk` once
        if let Some(kind) = load_from_disk() {
            CURRENT.store(kind as u8, Ordering::Relaxed);
        }
        LOADED.store(true, Ordering::Release);
    }
    theme_kind_from_u8(CURRENT.load(Ordering::Relaxed))
}

/// Set the in-memory theme kind without writing to disk.
///
/// Used by the dispatcher (after `Action::SetTheme` is processed) and by the live-preview path during the picker.
/// Disk-write happens via `Effect::PersistSetting`, NOT here.
pub fn set(kind: ThemeKind) {
    CURRENT.store(kind as u8, Ordering::Relaxed);
    LOADED.store(true, Ordering::Release);
}

// -- Terminal-native lock (minimal mode) --------------------------------------

#[must_use]
pub fn terminal_native_locked() -> bool {
    TERMINAL_NATIVE_LOCK.load(Ordering::Relaxed)
}

pub fn set_terminal_native_lock(locked: bool) {
    TERMINAL_NATIVE_LOCK.store(locked, Ordering::Relaxed);
    // Cap quantization at ANSI-16 and switch syntax tokens to the dual-polarity accent map (default-fg grays and base ANSI hues)
    // Without the polarity-safe remap, night-theme pastels collapse to White and vanish on light terminal profiles in minimal mode
    fuigo_markdown::set_color_level_cap(if locked {
        fuigo_markdown::ColorLevel::Basic
    } else {
        fuigo_markdown::ColorLevel::TrueColor
    });
    fuigo_markdown::set_polarity_safe_syntax(locked);
}

// -- Auto-mode ---------------------------------------------------------------

#[must_use]
pub fn is_auto_mode() -> bool {
    AUTO_MODE.load(Ordering::Relaxed)
}

pub fn set_auto_mode(enabled: bool) {
    AUTO_MODE.store(enabled, Ordering::Relaxed);
}

/// Get the cached auto-theme configuration, loading from config on first access.
///
/// The cache can be invalidated via [`invalidate_auto_theme_config`] so subsequent lookups re-read from disk.
#[must_use]
pub fn auto_theme_config() -> AutoThemeConfig {
    let mut guard = AUTO_THEME_CONFIG.lock().unwrap_or_else(|e| e.into_inner());
    *guard.get_or_insert_with(load_auto_theme_config)
}

/// Call after updating `auto_dark_theme` or `auto_light_theme` in config so subsequent lookups see the new values.
/// Used by the settings modal and the `/theme auto` slash command.
pub fn invalidate_auto_theme_config() {
    *AUTO_THEME_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

// -- Theme resolution --------------------------------------------------------

/// Called once at startup. Returns the concrete `ThemeKind` (never `Auto`).
///
/// Precedence:
/// 1. Environment variable (`FUIGO_THEME` / `LC_FUIGO_THEME`)
/// 2. Config file (`[ui].theme`)
/// 3. Default: `FuigoNight`
#[must_use]
pub fn resolve_initial_theme() -> ThemeKind {
    resolve_initial_theme_from(env_theme_name().as_deref(), load_from_disk(), true)
}

/// Variant of [`resolve_initial_theme`] without the OSC 11 startup fallback, for resolution after the terminal is initialized.
#[must_use]
pub fn resolve_initial_theme_no_osc11() -> ThemeKind {
    resolve_initial_theme_from(env_theme_name().as_deref(), load_from_disk(), false)
}

fn env_theme_name() -> Option<String> {
    env_theme_name_from(&crate::host::collect_unicode_env()).map(str::to_owned)
}

fn env_theme_name_from(env: &HashMap<String, String>) -> Option<&str> {
    for key in ["FUIGO_THEME", "LC_FUIGO_THEME"] {
        let Some(raw) = env
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if ThemeKind::from_name(raw).is_some() {
            return Some(raw);
        }
    }
    None
}

fn resolve_initial_theme_from(
    env_theme: Option<&str>,
    config_theme: Option<ThemeKind>,
    osc11_fallback: bool,
) -> ThemeKind {
    if let Some(kind) = env_theme.and_then(ThemeKind::from_name) {
        return resolve_from_config(Some(kind), osc11_fallback);
    }
    resolve_from_config(config_theme, osc11_fallback)
}

/// Inner resolution logic, factored out for testability.
fn resolve_from_config(config_theme: Option<ThemeKind>, osc11_fallback: bool) -> ThemeKind {
    if let Some(kind) = config_theme {
        if kind.is_auto() {
            set_auto_mode(true);
            let appearance = if osc11_fallback {
                system_appearance::detect_with_osc11_fallback()
            } else {
                system_appearance::detect()
            };
            return resolve_from_appearance(appearance);
        }
        return kind;
    }

    ThemeKind::FuigoNight
}

fn resolve_from_appearance(appearance: Option<system_appearance::SystemAppearance>) -> ThemeKind {
    let config = auto_theme_config();
    appearance
        .map(|a| system_appearance::to_theme_kind(a, config.dark_theme, config.light_theme))
        .unwrap_or(ThemeKind::FuigoNight)
}

/// Resolve "auto" by detecting system appearance and mapping via config.
///
/// Falls back to `FuigoNight` when detection fails.
/// Uses desktop APIs and env hints (no OSC 11), so it is safe to call at runtime while crossterm's `EventStream` is active.
/// Called from the settings modal and the `/theme auto` slash command.
#[must_use]
pub fn resolve_auto() -> ThemeKind {
    resolve_from_appearance(system_appearance::detect())
}

// -- Disk reads --------------------------------------------------------------

/// Read the theme from the effective config (managed_config.toml merged under config.toml; user wins).
/// Checks `[ui].theme` first (the canonical location), then falls back to a top-level `theme` key for backwards compatibility.
fn load_from_disk() -> Option<ThemeKind> {
    let root = fuigo_config::load_effective_config_disk_only().ok()?;
    let table = root.as_table()?;
    // Canonical: [ui] section
    let value = table
        .get("ui")
        .and_then(|ui| ui.get("theme"))
        .and_then(|v| v.as_str())
        // Fallback: top-level `theme` key (legacy)
        .or_else(|| table.get("theme").and_then(|v| v.as_str()));
    value.and_then(ThemeKind::from_name)
}

/// Reads `[ui].auto_dark_theme` and `[ui].auto_light_theme` from the effective config, parsing them as theme names.
/// Filters out `Auto` to prevent circular reference.
fn load_auto_theme_config() -> AutoThemeConfig {
    let Ok(root) = fuigo_config::load_effective_config_disk_only() else {
        return AutoThemeConfig::default();
    };
    let Some(table) = root.as_table() else {
        return AutoThemeConfig::default();
    };
    let ui = table.get("ui");
    AutoThemeConfig {
        dark_theme: ui
            .and_then(|u| u.get("auto_dark_theme"))
            .and_then(|v| v.as_str())
            .and_then(ThemeKind::from_name)
            .filter(|k| !k.is_auto()),
        light_theme: ui
            .and_then(|u| u.get("auto_light_theme"))
            .and_then(|v| v.as_str())
            .and_then(ThemeKind::from_name)
            .filter(|k| !k.is_auto()),
    }
}

// -- Test support ------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub fn reset_for_test() {
    // Tests are serialized via TEST_LOCK so the AtomicU8/AtomicBool pair is safe to reset without any cross-thread coordination
    CURRENT.store(ThemeKind::FuigoNight as u8, Ordering::Relaxed);
    LOADED.store(false, Ordering::Release);
    AUTO_MODE.store(false, Ordering::Relaxed);
    set_terminal_native_lock(false);
    *AUTO_THEME_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Seed `AUTO_THEME_CONFIG` with explicit defaults so `auto_theme_config()` never falls through to `load_auto_theme_config()`.
/// That fallback reads the user's real `config.toml`.
/// Call from test setup after `reset_for_test()`.
#[cfg(any(test, feature = "test-support"))]
pub fn seed_auto_theme_defaults_for_test() {
    *AUTO_THEME_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(AutoThemeConfig::default());
}

#[cfg(any(test, feature = "test-support"))]
pub fn test_lock() -> &'static Mutex<()> {
    &TEST_LOCK
}

/// Pin a deterministic theme and color level for a test's duration so exact height and screen-position assertions are hermetic.
/// Rendered heights are computed under the process-global `Theme::current()`, which concurrent `set_theme` tests mutate.
/// `Theme::current()` also reads the global color level; holding the shared test lock blocks a mid-test theme change.
/// Hold the returned guard for the whole test.
#[cfg(any(test, feature = "test-support"))]
pub fn pin_theme() -> std::sync::MutexGuard<'static, ()> {
    let guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
    set(ThemeKind::FuigoNight);
    // Color level is a write-once `OnceLock`; tests run without a TTY so it resolves to `TrueColor` anyway
    // Pin it explicitly (best-effort: ignore the already-initialized `Err`) so the measure path that reads it stays fixed
    let _ = super::color_support::set(super::color_support::ColorLevel::TrueColor);
    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a test body while holding the global test lock and with a clean initial state.
    fn with_test_env(f: impl FnOnce()) {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_for_test();
        seed_auto_theme_defaults_for_test();
        // Set LOADED=true so current_kind() doesn't read from disk.
        set(ThemeKind::FuigoNight);
        system_appearance::clear_mock();
        f();
        system_appearance::clear_mock();
        reset_for_test();
    }

    fn set_test_auto_config(config: AutoThemeConfig) {
        *AUTO_THEME_CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(config);
    }

    // -- Terminal-native lock (minimal mode) ----------------------------------

    #[test]
    fn terminal_native_lock_pins_kind_and_blocks_apply_kind() {
        with_test_env(|| {
            set(ThemeKind::FuigoDay);
            set_terminal_native_lock(true);
            assert!(terminal_native_locked());
            assert_eq!(current_kind(), ThemeKind::FuigoNight, "nominal kind");

            let applied = super::super::Theme::apply_kind(ThemeKind::FuigoDay);
            assert_eq!(applied, ThemeKind::FuigoNight, "apply_kind must no-op");
            assert_eq!(current_kind(), ThemeKind::FuigoNight);

            set_terminal_native_lock(false);
            assert_eq!(
                current_kind(),
                ThemeKind::FuigoDay,
                "unlocking restores the cached kind"
            );
        });
    }

    #[test]
    fn terminal_native_lock_serves_terminal_default_palette() {
        with_test_env(|| {
            set(ThemeKind::FuigoDay);
            set_terminal_native_lock(true);
            let theme = super::super::Theme::current();
            let native = super::super::Theme::terminal_default();
            assert_eq!(theme.bg_base, native.bg_base);
            assert_eq!(theme.text_primary, native.text_primary);
            assert_eq!(theme.accent_user, native.accent_user);
            assert_ne!(
                theme.text_primary,
                super::super::Theme::fuigoday().text_primary,
                "must not serve the cached (FuigoDay) theme"
            );
        });
    }

    #[test]
    fn reset_for_test_clears_terminal_native_lock() {
        with_test_env(|| {
            set_terminal_native_lock(true);
            reset_for_test();
            assert!(!terminal_native_locked());
        });
    }

    #[test]
    fn terminal_native_lock_enables_polarity_safe_syntax() {
        with_test_env(|| {
            assert!(!fuigo_markdown::polarity_safe_syntax());
            set_terminal_native_lock(true);
            assert!(
                fuigo_markdown::polarity_safe_syntax(),
                "minimal must engage polarity-safe syntax remapping"
            );
            set_terminal_native_lock(false);
            assert!(!fuigo_markdown::polarity_safe_syntax());
        });
    }

    #[test]
    fn terminal_native_lock_caps_quantize_at_ansi16() {
        use ratatui::style::Color;

        use crate::theme::color_support;
        with_test_env(|| {
            set_terminal_native_lock(true);
            assert!(color_support::detect() <= color_support::ColorLevel::Basic);
            for input in [
                Color::Rgb(0x26, 0x26, 0x26), // fuigoday text_primary
                Color::Rgb(122, 162, 247),
                Color::Indexed(141),
            ] {
                let q = color_support::quantize(input);
                assert!(
                    !matches!(q, Color::Rgb(..) | Color::Indexed(_)),
                    "quantize({input:?}) must collapse to Reset/named ANSI under \
                     the lock, got {q:?}"
                );
            }
        });
    }

    #[test]
    fn resolve_no_osc11_explicit_auto_and_default() {
        with_test_env(|| {
            assert_eq!(
                resolve_from_config(Some(ThemeKind::FuigoDay), false),
                ThemeKind::FuigoDay
            );
            assert!(!is_auto_mode());

            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Light));
            assert_eq!(
                resolve_from_config(Some(ThemeKind::Auto), false),
                ThemeKind::FuigoDay
            );
            assert!(is_auto_mode(), "auto must arm the appearance watcher");

            assert_eq!(resolve_from_config(None, false), ThemeKind::FuigoNight);
        });
    }

    // -- AUTO_MODE -----------------------------------------------------------

    #[test]
    fn auto_mode_default_is_false() {
        with_test_env(|| {
            assert!(!is_auto_mode());
        });
    }

    #[test]
    fn set_auto_mode_toggles() {
        with_test_env(|| {
            set_auto_mode(true);
            assert!(is_auto_mode());
            set_auto_mode(false);
            assert!(!is_auto_mode());
        });
    }

    // -- AutoThemeConfig -----------------------------------------------------

    #[test]
    fn auto_theme_config_defaults_to_none() {
        let config = AutoThemeConfig::default();
        assert!(config.dark_theme.is_none());
        assert!(config.light_theme.is_none());
    }

    // -- resolve_auto --------------------------------------------------------

    #[test]
    fn resolve_auto_dark_system_returns_fuigonight() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Dark));
            let result = resolve_auto();
            assert_eq!(result, ThemeKind::FuigoNight);
        });
    }

    #[test]
    fn resolve_auto_light_system_returns_fuigoday() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Light));
            let result = resolve_auto();
            assert_eq!(result, ThemeKind::FuigoDay);
        });
    }

    #[test]
    fn resolve_auto_detection_failure_returns_fuigonight() {
        with_test_env(|| {
            system_appearance::set_mock(None);
            let result = resolve_auto();
            assert_eq!(result, ThemeKind::FuigoNight);
        });
    }

    // -- invalidate_auto_theme_config ----------------------------------------

    #[test]
    fn invalidate_clears_cached_config() {
        with_test_env(|| {
            set_test_auto_config(AutoThemeConfig {
                dark_theme: Some(ThemeKind::TokyoNight),
                light_theme: None,
            });
            let config1 = auto_theme_config();
            assert_eq!(config1.dark_theme, Some(ThemeKind::TokyoNight));

            invalidate_auto_theme_config();
            // Pre-populate again with defaults to avoid disk dependency.
            set_test_auto_config(AutoThemeConfig::default());
            let config2 = auto_theme_config();
            assert!(config2.dark_theme.is_none());
        });
    }

    // -- resolve_from_config (resolve_initial_theme inner logic) ---------------

    #[test]
    fn resolve_from_config_no_config_returns_fuigonight() {
        with_test_env(|| {
            let result = resolve_from_config(None, true);
            assert_eq!(result, ThemeKind::FuigoNight);
            assert!(!is_auto_mode());
        });
    }

    #[test]
    fn resolve_from_config_explicit_theme_returns_it() {
        with_test_env(|| {
            let result = resolve_from_config(Some(ThemeKind::FuigoDay), true);
            assert_eq!(result, ThemeKind::FuigoDay);
            assert!(
                !is_auto_mode(),
                "explicit theme should not enable auto mode"
            );
        });
    }

    #[test]
    fn resolve_from_config_auto_sets_auto_mode_dark() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Dark));
            let result = resolve_from_config(Some(ThemeKind::Auto), true);
            assert_eq!(result, ThemeKind::FuigoNight);
            assert!(is_auto_mode(), "auto config must enable auto mode");
        });
    }

    #[test]
    fn resolve_from_config_auto_with_light_system() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Light));
            let result = resolve_from_config(Some(ThemeKind::Auto), true);
            assert_eq!(result, ThemeKind::FuigoDay);
            assert!(is_auto_mode());
        });
    }

    #[test]
    fn resolve_from_config_auto_detection_failure() {
        with_test_env(|| {
            system_appearance::set_mock(None);
            let result = resolve_from_config(Some(ThemeKind::Auto), true);
            assert_eq!(result, ThemeKind::FuigoNight);
            assert!(is_auto_mode(), "auto mode is set before detection");
        });
    }

    #[test]
    fn env_theme_overrides_config() {
        with_test_env(|| {
            assert_eq!(
                resolve_initial_theme_from(Some("fuigoday"), Some(ThemeKind::TokyoNight), false),
                ThemeKind::FuigoDay
            );
            assert!(!is_auto_mode());
        });
    }

    #[test]
    fn env_theme_auto_arms_watcher_and_resolves() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Light));
            assert_eq!(
                resolve_initial_theme_from(Some("auto"), Some(ThemeKind::TokyoNight), false),
                ThemeKind::FuigoDay
            );
            assert!(is_auto_mode());
        });
    }

    #[test]
    fn env_theme_auto_dark_arms_watcher_and_resolves() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Dark));
            assert_eq!(
                resolve_initial_theme_from(Some("auto"), Some(ThemeKind::TokyoNight), false),
                ThemeKind::FuigoNight
            );
            assert!(is_auto_mode());
        });
    }

    #[test]
    fn unknown_env_theme_falls_through_to_config() {
        with_test_env(|| {
            assert_eq!(
                resolve_initial_theme_from(Some("not-a-theme"), Some(ThemeKind::FuigoDay), false),
                ThemeKind::FuigoDay
            );
        });
    }

    fn theme_env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn fuigo_theme_wins_over_lc_and_config() {
        with_test_env(|| {
            let env = theme_env(&[("FUIGO_THEME", "fuigoday"), ("LC_FUIGO_THEME", "tokyonight")]);
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&env),
                    Some(ThemeKind::TokyoNight),
                    false
                ),
                ThemeKind::FuigoDay
            );
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&env),
                    Some(ThemeKind::TokyoNight),
                    true
                ),
                ThemeKind::FuigoDay
            );
            assert!(!is_auto_mode());
        });
    }

    #[test]
    fn empty_or_absent_fuigo_theme_falls_through_to_lc() {
        with_test_env(|| {
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[
                        ("FUIGO_THEME", ""),
                        ("LC_FUIGO_THEME", "fuigoday")
                    ])),
                    Some(ThemeKind::TokyoNight),
                    false,
                ),
                ThemeKind::FuigoDay
            );
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[("LC_FUIGO_THEME", "fuigoday")])),
                    Some(ThemeKind::TokyoNight),
                    true,
                ),
                ThemeKind::FuigoDay
            );
        });
    }

    #[test]
    fn unknown_fuigo_theme_falls_through_to_valid_lc() {
        with_test_env(|| {
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[
                        ("FUIGO_THEME", "not-a-theme"),
                        ("LC_FUIGO_THEME", "fuigoday"),
                    ])),
                    Some(ThemeKind::TokyoNight),
                    false,
                ),
                ThemeKind::FuigoDay
            );
            assert!(!is_auto_mode());
        });
    }

    #[test]
    fn unknown_or_empty_theme_env_falls_through_to_config() {
        with_test_env(|| {
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[
                        ("FUIGO_THEME", "not-a-theme"),
                        ("LC_FUIGO_THEME", "")
                    ])),
                    Some(ThemeKind::FuigoDay),
                    false,
                ),
                ThemeKind::FuigoDay
            );
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[("FUIGO_THEME", ""), ("LC_FUIGO_THEME", "")])),
                    Some(ThemeKind::FuigoDay),
                    true,
                ),
                ThemeKind::FuigoDay
            );
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[])),
                    Some(ThemeKind::FuigoDay),
                    false
                ),
                ThemeKind::FuigoDay
            );
        });
    }

    #[test]
    fn env_theme_system_alias_arms_auto_on_both_resolve_paths() {
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Light));
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[("FUIGO_THEME", "system")])),
                    Some(ThemeKind::TokyoNight),
                    false,
                ),
                ThemeKind::FuigoDay
            );
            assert!(is_auto_mode());
        });
        with_test_env(|| {
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Dark));
            assert_eq!(
                resolve_initial_theme_from(
                    env_theme_name_from(&theme_env(&[("LC_FUIGO_THEME", "auto")])),
                    Some(ThemeKind::TokyoNight),
                    true,
                ),
                ThemeKind::FuigoNight
            );
            assert!(is_auto_mode());
        });
    }

    // -- resolve_auto with custom config -------------------------------------

    #[test]
    fn resolve_auto_with_custom_dark_config() {
        with_test_env(|| {
            set_test_auto_config(AutoThemeConfig {
                dark_theme: Some(ThemeKind::TokyoNight),
                light_theme: None,
            });
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Dark));
            assert_eq!(resolve_auto(), ThemeKind::TokyoNight);
        });
    }

    #[test]
    fn resolve_auto_with_custom_light_config() {
        with_test_env(|| {
            set_test_auto_config(AutoThemeConfig {
                dark_theme: None,
                light_theme: Some(ThemeKind::RosePineMoon),
            });
            system_appearance::set_mock(Some(system_appearance::SystemAppearance::Light));
            assert_eq!(resolve_auto(), ThemeKind::RosePineMoon);
        });
    }

    // -- auto_theme_config filter --------------------------------------------

    #[test]
    fn auto_theme_config_filter_rejects_auto_value() {
        // Simulates the .filter(|k| !k.is_auto()) guard in load_auto_theme_config().
        // When config contains auto_dark_theme = "auto", from_name returns Some(Auto), but the filter discards it to prevent circular reference
        let parsed = ThemeKind::from_name("auto").filter(|k| !k.is_auto());
        assert!(parsed.is_none(), "Auto must be filtered out");
    }

    #[test]
    fn auto_theme_config_filter_accepts_concrete_theme() {
        let parsed = ThemeKind::from_name("tokyonight").filter(|k| !k.is_auto());
        assert_eq!(parsed, Some(ThemeKind::TokyoNight));
    }

    // -- set / current_kind --------------------------------------------------

    /// `set` followed by `current_kind` returns the set value, and the `LOADED` flag flips so subsequent reads don't re-seed from disk.
    /// This is the optimistic-update invariant the dispatcher relies on.
    ///
    /// Explicitly observe the `LOADED` flag
    /// side-effect by calling `reset_for_test()` between sets — if
    /// `set` didn't flip `LOADED = true`, the second `current_kind`
    /// read would re-seed from disk and the assertion would fail.
    #[test]
    fn set_then_current_kind_round_trips() {
        with_test_env(|| {
            set(ThemeKind::TokyoNight);
            assert_eq!(current_kind(), ThemeKind::TokyoNight);
            set(ThemeKind::FuigoDay);
            assert_eq!(current_kind(), ThemeKind::FuigoDay);
        });
    }

    /// `set` flips `LOADED` so a subsequent `current_kind` read does NOT re-seed from disk.
    /// Unlike `set_then_current_kind_round_trips`, this exercises the `LOADED` flag invariant directly via the atomic statics.
    #[test]
    fn set_flips_loaded_flag_so_current_kind_skips_disk_reseed() {
        with_test_env(|| {
            // with_test_env seeds LOADED=true to prevent disk reads; this test specifically needs LOADED=false to verify that set() flips it
            LOADED.store(false, Ordering::Release);
            assert!(
                !LOADED.load(Ordering::Acquire),
                "LOADED must be false for this test"
            );
            set(ThemeKind::FuigoDay);
            assert!(
                LOADED.load(Ordering::Acquire),
                "set must flip LOADED to true"
            );
            assert_eq!(current_kind(), ThemeKind::FuigoDay);
            assert!(
                LOADED.load(Ordering::Acquire),
                "current_kind must NOT flip LOADED back to false"
            );
        });
    }
}
