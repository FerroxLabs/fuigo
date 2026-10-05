use crate::util::config::RemoteSettings;
use toml::Value as TomlValue;

/// Env override for the full crash-handler install gate.
pub(crate) const ENV_CRASH_HANDLER: &str = "FUIGO_CRASH_HANDLER";

fn crash_handler_from_toml(v: Option<&TomlValue>) -> Option<bool> {
    v?.get("diagnostics")?.get("crash_handler")?.as_bool()
}

/// Default when no layer sets the gate: crash recording is ON (Fuigo 1.0.21). Reports stay local
/// under `$FUIGO_HOME/crash/`; any layer can turn it off.
pub(crate) const CRASH_HANDLER_DEFAULT: bool = true;

/// Precedence core shared by the typed resolver and the disk reader so they can't drift.
/// Order: requirement > env > config > managed > remote > default `true`.
fn resolve_crash_handler_enabled_layers(
    requirement: Option<bool>,
    config: Option<bool>,
    managed: Option<bool>,
    feature_flag: Option<bool>,
) -> crate::agent::config::Resolved<bool> {
    use crate::agent::config::BoolFlag;
    BoolFlag::env(ENV_CRASH_HANDLER)
        .requirement(requirement)
        .config(config)
        .managed(managed)
        .feature_flag(feature_flag)
        .default(CRASH_HANDLER_DEFAULT)
        .resolve()
}

/// Precedence: requirements > env (`FUIGO_CRASH_HANDLER`) > user `[diagnostics] crash_handler` > managed > remote settings `crash_handler_enabled`.
/// Defaults to `true`; `false` at any layer (or `FUIGO_CRASH_HANDLER=0`) turns it off.
pub fn resolve_crash_handler_enabled(
    requirements: Option<&TomlValue>,
    user: Option<&TomlValue>,
    managed: Option<&TomlValue>,
    remote: Option<&RemoteSettings>,
) -> crate::agent::config::Resolved<bool> {
    resolve_crash_handler_enabled_layers(
        crash_handler_from_toml(requirements),
        crash_handler_from_toml(user),
        crash_handler_from_toml(managed),
        remote.and_then(|r| r.crash_handler_enabled),
    )
}

/// Process-global cache of the remote tier, read by [`load_crash_handler_enabled_sync`] before Tokio starts, when no live `RemoteSettings` exists.
/// Fail-safe to `None` on lock poisoning.
static REMOTE_CRASH_HANDLER_ENABLED: std::sync::RwLock<Option<bool>> = std::sync::RwLock::new(None);

/// Called when the agent applies `RemoteSettings`.
///
/// A delivered value is also persisted under `$FUIGO_HOME/crash/remote-gate`, because the install
/// decision runs at the top of `main`, before any remote settings arrive: without it a remote
/// `crash_handler_enabled = false` kill switch could never stop the (default-on) recorder. The
/// persisted value is sticky — an absent value (settings not fetched yet, or offline) leaves it
/// in place, and a later `true` lifts it.
///
/// A `false` that turns the effective gate off (no higher tier keeps it on) also stops recording
/// in this session, through the hook the binary registered with
/// [`set_crash_recording_stop_hook`]. Turning it back on applies from the next start.
pub(crate) fn cache_remote_crash_handler_enabled(value: Option<bool>) {
    if let Ok(mut guard) = REMOTE_CRASH_HANDLER_ENABLED.write() {
        *guard = value;
    }
    #[cfg(not(test))]
    if let Some(v) = value {
        persist_remote_gate(&persisted_remote_gate_path(), v);
    }
    stop_recording_if_gate_now_off(
        value,
        load_crash_handler_enabled_sync,
        CRASH_RECORDING_STOP_HOOK.get().copied(),
    );
}

/// How the binary stops crash recording mid-session (it closes and deletes this process's crash
/// slot). A hook instead of a call keeps `fuigo-shell` free of a dependency on the crash crate:
/// the composition root (`fuigo-pager-bin`), which already owns the recorder, registers it.
static CRASH_RECORDING_STOP_HOOK: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Register the function that stops crash recording for the rest of this session. Called once by
/// the binary right after the recorder is installed; later calls are ignored.
pub fn set_crash_recording_stop_hook(hook: fn()) {
    let _ = CRASH_RECORDING_STOP_HOOK.set(hook);
}

/// Run `hook` when a delivered remote value is `false` and the gate it feeds, re-resolved with
/// full precedence by `effective`, is now off. Returns whether the hook ran.
fn stop_recording_if_gate_now_off(
    value: Option<bool>,
    effective: impl FnOnce() -> bool,
    hook: Option<fn()>,
) -> bool {
    match (value, hook) {
        (Some(false), Some(hook)) if !effective() => {
            hook();
            true
        }
        _ => false,
    }
}

fn cached_remote_crash_handler_enabled() -> Option<bool> {
    REMOTE_CRASH_HANDLER_ENABLED.read().ok().and_then(|g| *g)
}

fn persisted_remote_gate_path() -> std::path::PathBuf {
    crate::util::fuigo_home::fuigo_home()
        .join("crash")
        .join("remote-gate")
}

/// Best-effort and atomic: the value goes to a unique temporary sibling that is renamed over the
/// gate, so a concurrent startup never reads a truncated file and a failed write keeps the
/// previous value.
fn persist_remote_gate(path: &std::path::Path, value: bool) {
    let Some(dir) = path.parent() else {
        return;
    };
    let _ = std::fs::create_dir_all(dir);
    let tmp = dir.join(format!(".remote-gate.tmp-{}", std::process::id()));
    let written = std::fs::write(&tmp, if value { "1\n" } else { "0\n" })
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

fn read_persisted_remote_gate(path: &std::path::Path) -> Option<bool> {
    match std::fs::read_to_string(path).ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Merge system-managed policy (`/etc/fuigo`) under home `managed_config.toml` so MDM/system layers still reach the managed BoolFlag tier.
fn load_managed_toml_layers() -> Option<TomlValue> {
    let system = crate::config::load_system_managed_config().ok();
    let managed = crate::config::load_managed_config().ok();
    match (system, managed) {
        (None, None) => None,
        (Some(s), None) => Some(s),
        (None, Some(m)) => Some(m),
        (Some(mut s), Some(m)) => {
            fuigo_config::deep_merge_toml(&mut s, &m);
            Some(s)
        }
    }
}

/// Free-function form of [`resolve_crash_handler_enabled`] for the pager-bin install path, which has no live `RemoteSettings`.
/// Defaults to `true`.
pub fn load_crash_handler_enabled_sync() -> bool {
    let requirements = crate::config::load_merged_requirements();
    let user = crate::config::load_from_disk().ok();
    let managed = load_managed_toml_layers();
    resolve_crash_handler_enabled_layers(
        crash_handler_from_toml(requirements.as_ref()),
        crash_handler_from_toml(user.as_ref()),
        crash_handler_from_toml(managed.as_ref()),
        cached_remote_crash_handler_enabled()
            .or_else(|| read_persisted_remote_gate(&persisted_remote_gate_path())),
    )
    .value
}

#[cfg(test)]
mod crash_handler_gate_tests {
    use super::*;
    use crate::agent::config::ConfigSource;

    // `FUIGO_CRASH_HANDLER` is process-global
    // Serialize and force it unset at the top of each test so a developer's shell value can't make these flaky
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn guard() -> std::sync::MutexGuard<'static, ()> {
        let g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var(ENV_CRASH_HANDLER) };
        g
    }

    fn toml_diag(v: bool) -> TomlValue {
        toml::from_str(&format!("[diagnostics]\ncrash_handler = {v}\n")).unwrap()
    }

    fn remote(v: Option<bool>) -> RemoteSettings {
        RemoteSettings {
            crash_handler_enabled: v,
            ..RemoteSettings::default()
        }
    }

    #[test]
    fn defaults_on_when_nothing_set() {
        let _g = guard();
        let r = resolve_crash_handler_enabled(None, None, None, None);
        assert!(r.value, "crash recording must default ON");
        assert_eq!(r.source, ConfigSource::Default);
        let r = resolve_crash_handler_enabled(None, None, None, Some(&remote(None)));
        assert!(r.value, "an unset remote tier keeps the default");
        assert_eq!(r.source, ConfigSource::Default);
    }

    #[test]
    fn user_config_false_turns_the_default_off() {
        let _g = guard();
        let off = toml_diag(false);
        let r = resolve_crash_handler_enabled(None, Some(&off), None, None);
        assert!(
            !r.value,
            "[diagnostics] crash_handler = false must win over the default"
        );
        assert_eq!(r.source, ConfigSource::Config);
    }

    #[test]
    fn env_zero_turns_the_default_off() {
        let _g = guard();
        unsafe { std::env::set_var(ENV_CRASH_HANDLER, "0") };
        let r = resolve_crash_handler_enabled(None, None, None, None);
        unsafe { std::env::remove_var(ENV_CRASH_HANDLER) };
        assert!(!r.value, "FUIGO_CRASH_HANDLER=0 must win over the default");
        assert_eq!(r.source, ConfigSource::Env);
    }

    #[test]
    fn each_layer_can_turn_it_on() {
        let _g = guard();
        let on = toml_diag(true);
        let r = resolve_crash_handler_enabled(Some(&on), None, None, None);
        assert!(r.value);
        assert_eq!(r.source, ConfigSource::Requirement);
        let r = resolve_crash_handler_enabled(None, Some(&on), None, None);
        assert!(r.value);
        assert_eq!(r.source, ConfigSource::Config);
        let r = resolve_crash_handler_enabled(None, None, Some(&on), None);
        assert!(r.value);
        assert_eq!(r.source, ConfigSource::ManagedConfig);
        let r = resolve_crash_handler_enabled(None, None, None, Some(&remote(Some(true))));
        assert!(r.value);
        assert_eq!(r.source, ConfigSource::Remote);
    }

    #[test]
    fn each_layer_can_force_disable() {
        let _g = guard();
        let off = toml_diag(false);
        let r = resolve_crash_handler_enabled(Some(&off), None, None, Some(&remote(Some(true))));
        assert!(!r.value);
        assert_eq!(r.source, ConfigSource::Requirement);
        let r = resolve_crash_handler_enabled(None, Some(&off), None, Some(&remote(Some(true))));
        assert!(!r.value);
        assert_eq!(r.source, ConfigSource::Config);
        let r = resolve_crash_handler_enabled(None, None, Some(&off), Some(&remote(Some(true))));
        assert!(!r.value);
        assert_eq!(r.source, ConfigSource::ManagedConfig);
    }

    #[test]
    fn remote_kill_switch_reads_struct_field() {
        let _g = guard();
        let r = resolve_crash_handler_enabled(None, None, None, Some(&remote(Some(false))));
        assert!(!r.value);
        assert_eq!(r.source, ConfigSource::Remote);
        let r = resolve_crash_handler_enabled(None, None, None, Some(&remote(None)));
        assert!(r.value, "no remote value: the ON default applies");
        assert_eq!(r.source, ConfigSource::Default);
    }

    #[test]
    fn precedence_config_beats_managed_beats_remote() {
        let _g = guard();
        let off = toml_diag(false);
        let on = toml_diag(true);
        let r =
            resolve_crash_handler_enabled(None, Some(&off), Some(&on), Some(&remote(Some(true))));
        assert!(!r.value);
        assert_eq!(r.source, ConfigSource::Config);
        let r = resolve_crash_handler_enabled(None, None, Some(&off), Some(&remote(Some(true))));
        assert!(!r.value);
        assert_eq!(r.source, ConfigSource::ManagedConfig);
    }

    #[test]
    fn env_overrides_config_and_remote() {
        let _g = guard();
        unsafe { std::env::set_var(ENV_CRASH_HANDLER, "1") };
        let off = toml_diag(false);
        let r = resolve_crash_handler_enabled(None, Some(&off), None, Some(&remote(Some(false))));
        assert!(r.value, "env must override config + remote");
        assert_eq!(r.source, ConfigSource::Env);
        unsafe { std::env::remove_var(ENV_CRASH_HANDLER) };
    }

    #[test]
    fn env_can_force_disable_over_config() {
        let _g = guard();
        unsafe { std::env::set_var(ENV_CRASH_HANDLER, "0") };
        let on = toml_diag(true);
        let r = resolve_crash_handler_enabled(None, Some(&on), None, Some(&remote(Some(true))));
        assert!(!r.value, "env=0 must override config + remote");
        assert_eq!(r.source, ConfigSource::Env);
        unsafe { std::env::remove_var(ENV_CRASH_HANDLER) };
    }

    #[test]
    fn requirement_beats_env() {
        let _g = guard();
        unsafe { std::env::set_var(ENV_CRASH_HANDLER, "1") };
        let off = toml_diag(false);
        let r = resolve_crash_handler_enabled(Some(&off), None, None, None);
        assert!(!r.value, "requirement must beat env");
        assert_eq!(r.source, ConfigSource::Requirement);
        unsafe { std::env::remove_var(ENV_CRASH_HANDLER) };
    }

    #[test]
    fn persisted_remote_kill_switch_reaches_the_startup_decision() {
        let _g = guard();
        let dir = std::env::temp_dir().join(format!("fuigo-crash-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("crash").join("remote-gate");
        assert_eq!(
            read_persisted_remote_gate(&path),
            None,
            "nothing persisted yet"
        );
        persist_remote_gate(&path, false);
        let remote = read_persisted_remote_gate(&path);
        assert_eq!(remote, Some(false));
        let r = resolve_crash_handler_enabled_layers(None, None, None, remote);
        assert!(
            !r.value,
            "a persisted remote kill switch turns the default off at startup"
        );
        assert_eq!(r.source, ConfigSource::Remote);
        let on = toml_diag(true);
        let r = resolve_crash_handler_enabled_layers(
            None,
            crash_handler_from_toml(Some(&on)),
            None,
            remote,
        );
        assert!(r.value, "user config still outranks the remote tier");
        // A failed replacement (the rename target is a directory) keeps the previous value
        // and leaves no temporary file behind.
        let blocked = dir.join("crash").join("blocked-gate");
        std::fs::create_dir_all(blocked.join("child")).expect("mkdir");
        persist_remote_gate(&blocked, true);
        assert!(
            blocked.is_dir(),
            "a failed replacement leaves the target untouched"
        );
        persist_remote_gate(&path, true);
        assert_eq!(
            read_persisted_remote_gate(&path),
            Some(true),
            "a later true lifts it"
        );
        let leftovers = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(leftovers, 0, "no temporary files left behind");
        std::fs::write(&path, "garbage").expect("write");
        assert_eq!(read_persisted_remote_gate(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    static STOPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    fn count_stop() {
        STOPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    #[test]
    fn remote_switch_off_stops_recording_only_when_the_gate_turns_off() {
        let _g = guard();
        let before = STOPS.load(std::sync::atomic::Ordering::SeqCst);
        let hook: Option<fn()> = Some(count_stop);
        assert!(stop_recording_if_gate_now_off(Some(false), || false, hook));
        assert!(
            !stop_recording_if_gate_now_off(Some(false), || true, hook),
            "a higher tier (config/env/managed/requirement) keeps it on"
        );
        assert!(!stop_recording_if_gate_now_off(Some(true), || false, hook));
        assert!(!stop_recording_if_gate_now_off(None, || false, hook));
        assert!(!stop_recording_if_gate_now_off(Some(false), || false, None));
        assert_eq!(STOPS.load(std::sync::atomic::Ordering::SeqCst), before + 1);
    }

    #[test]
    fn remote_cache_round_trips() {
        let _g = guard();
        cache_remote_crash_handler_enabled(Some(true));
        assert_eq!(cached_remote_crash_handler_enabled(), Some(true));
        cache_remote_crash_handler_enabled(Some(false));
        assert_eq!(cached_remote_crash_handler_enabled(), Some(false));
        cache_remote_crash_handler_enabled(None);
        assert_eq!(cached_remote_crash_handler_enabled(), None);
    }
}
