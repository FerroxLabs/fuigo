//! Shared announcement types, persistence, and formatting for Fuigo CLI apps.
//!
//! This crate provides the common logic used by `fuigo-shell` and `fuigo-pager` for handling announcements (banner notifications).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Announcement from remote settings or local override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export, optional_fields = nullable))]
pub struct RemoteAnnouncement {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub cta: Option<AnnouncementCta>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub dismissible: Option<bool>,
    #[serde(default)]
    pub persistent: Option<bool>,
}

/// Optional call-to-action on an announcement (clients render it as a clickable link/button).
/// The server only emits it with both fields non-empty and the url https; parsing here stays tolerant like the parent struct.
/// `caption` is optional dim helper text after the button; absent means none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export, optional_fields = nullable))]
pub struct AnnouncementCta {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
}

/// Payload for `fuigo/announcements/update` ACP notification.
// Name predates the method rename to `.../update`; renaming would churn the pager consumer.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(export))]
pub struct AnnouncementsRefreshed {
    // The wire value is a plain JSON number; ts-rs would map u64 to `bigint`.
    #[serde(rename = "gen")]
    #[cfg_attr(feature = "ts", ts(type = "number"))]
    pub r#gen: u64,
    #[serde(default)]
    pub announcements: Vec<RemoteAnnouncement>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

/// Stable per-announcement hide key: the trimmed non-empty `id`, else a content-derived fallback so id-less items are still hideable.
/// The fallback joins title/message with the unprintable unit separator (\x1f), so distinct title/message splits cannot collide.
/// Real ids cannot plausibly match the fallback.
pub fn announcement_hide_key(a: &RemoteAnnouncement) -> String {
    match a.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(id) => id.to_string(),
        None => format!(
            "content:{}\u{1f}{}",
            a.title.as_deref().unwrap_or_default(),
            a.message.as_deref().unwrap_or_default()
        ),
    }
}

/// Parse persisted hidden state into a set of hidden announcement ids.
/// Unknown fields are tolerated; malformed input yields an empty set.
/// The legacy `{"hidden": bool}` shape carries no ids to migrate, so it decays to empty.
/// The banner re-shows once and the next hide re-persists per-ID.
pub fn parse_hidden_announcement_ids(s: &str) -> BTreeSet<String> {
    #[derive(Deserialize)]
    struct State {
        #[serde(default)]
        hidden_ids: BTreeSet<String>,
    }
    serde_json::from_str::<State>(s)
        .map(|s| s.hidden_ids)
        .unwrap_or_default()
}

/// Serialize hidden announcement ids (writes only the `hidden_ids` shape).
/// The `BTreeSet`'s deterministic order keeps the on-disk file stable across writes.
pub fn serialize_hidden_announcement_ids(ids: &BTreeSet<String>) -> Option<String> {
    #[derive(Serialize)]
    struct State<'a> {
        hidden_ids: &'a BTreeSet<String>,
    }
    serde_json::to_string(&State { hidden_ids: ids }).ok()
}

/// Drop hidden ids whose announcement is no longer active; returns whether the set changed (so callers can persist).
/// Call this from real update paths only: a per-frame prune would churn on transient list states.
pub fn prune_hidden_announcement_ids(
    ids: &mut BTreeSet<String>,
    active: &[RemoteAnnouncement],
) -> bool {
    let live: BTreeSet<String> = active.iter().map(announcement_hide_key).collect();
    let before = ids.len();
    ids.retain(|id| live.contains(id));
    ids.len() != before
}

/// Read hidden announcement ids from `~/.fuigo/announcements.json`.
/// Returns an empty set (everything visible) on missing or malformed file.
pub async fn read_hidden_announcement_ids() -> BTreeSet<String> {
    let path = announcements_state_path();
    match tokio::fs::read_to_string(&path).await {
        Ok(s) => parse_hidden_announcement_ids(&s),
        Err(_) => BTreeSet::new(),
    }
}

/// Record dismissals in `~/.fuigo/announcements.json`: every id in `changed`
/// ends up hidden exactly when it is in `hidden`; every other id in the file is
/// kept as it is on disk.
///
/// A change, not a whole set (P72): this used to write the caller's whole
/// in-memory set, so a second pager (or the shell) that had hidden or shown an
/// announcement since this one loaded the file had that undone. The write is
/// the shared read-modify-write (`fuigo_config::fs_atomic::edit_state_file`),
/// serialized across processes, and replaces the file atomically (it was
/// written in place, so a reader could see it torn). Off the async runtime.
///
/// # Errors
///
/// The lock wait gave up, the file could not be read (it is then left alone
/// rather than replaced), or the write failed.
pub async fn update_hidden_announcement_ids(
    hidden: BTreeSet<String>,
    changed: BTreeSet<String>,
) -> std::io::Result<()> {
    let path = announcements_state_path();
    tokio::task::spawn_blocking(move || update_hidden_announcement_ids_at(&path, &hidden, &changed))
        .await
        .map_err(std::io::Error::other)?
}

/// [`update_hidden_announcement_ids`] on an explicit file, on this thread.
///
/// # Errors
///
/// As [`update_hidden_announcement_ids`].
pub fn update_hidden_announcement_ids_at(
    path: &Path,
    hidden: &BTreeSet<String>,
    changed: &BTreeSet<String>,
) -> std::io::Result<()> {
    use fuigo_config::fs_atomic::Edit;
    if changed.is_empty() {
        return Ok(());
    }
    fuigo_config::fs_atomic::edit_state_file(
        path,
        |bytes| {
            fuigo_config::write_through::stage_file_atomically_with(
                path,
                bytes,
                fuigo_config::write_through::NewFileMode::Default,
            )
        },
        |current| {
            let (mut ids, exists) = match current {
                // Malformed reads as nothing hidden, as `read_hidden_announcement_ids` does.
                Ok(Some(bytes)) => (parse_hidden_announcement_ids(&String::from_utf8_lossy(bytes)), true),
                Ok(None) => (BTreeSet::new(), false),
                Err(e) => return Err(std::io::Error::new(e.kind(), e.to_string())),
            };
            let before = ids.clone();
            for id in changed {
                if hidden.contains(id) {
                    ids.insert(id.clone());
                } else {
                    ids.remove(id);
                }
            }
            if exists && ids == before {
                return Ok(Edit::Keep(()));
            }
            let contents = serialize_hidden_announcement_ids(&ids)
                .ok_or_else(|| std::io::Error::other("could not serialize announcement state"))?;
            Ok(Edit::Replace {
                contents: contents.into_bytes(),
                value: (),
            })
        },
    )
    .map_err(std::io::Error::from)
}

fn announcements_state_path() -> PathBuf {
    fuigo_tools::util::fuigo_home::fuigo_home().join("announcements.json")
}

// ─────────────────────────────────────────────────────────────────────────────
// Filtering
// ─────────────────────────────────────────────────────────────────────────────

/// Return only announcements with non-empty (trimmed) messages.
pub fn visible_announcements(announcements: &[RemoteAnnouncement]) -> Vec<&RemoteAnnouncement> {
    announcements
        .iter()
        .filter(|a| {
            a.message
                .as_ref()
                .map(|m| !m.trim().is_empty())
                .unwrap_or(false)
        })
        .collect()
}

/// Filter out announcements whose `expires_at` is in the past.
pub fn filter_expired(
    announcements: impl IntoIterator<Item = RemoteAnnouncement>,
) -> Vec<RemoteAnnouncement> {
    filter_expired_at(announcements, Utc::now())
}

/// [`filter_expired`] with an injectable clock.
/// The clock lets a unit test cross an expiry (an item live at the last check has since passed `expires_at`).
pub fn filter_expired_at(
    announcements: impl IntoIterator<Item = RemoteAnnouncement>,
    now: DateTime<Utc>,
) -> Vec<RemoteAnnouncement> {
    announcements
        .into_iter()
        .filter(|a| !is_expired_at(a, now))
        .collect()
}

/// Whether `expires_at` parses and is at/behind `now`; missing/unparseable never expires.
/// Strict `dt > now` keeps an item live only before its expiry.
/// Each call is allocation-free, so draw-time consumers can check every frame.
pub fn is_expired_at(a: &RemoteAnnouncement, now: DateTime<Utc>) -> bool {
    if let Some(exp) = &a.expires_at
        && let Ok(dt) = DateTime::parse_from_rfc3339(exp)
    {
        return dt <= now;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup resolution
// ─────────────────────────────────────────────────────────────────────────────

/// The `FUIGO_ANNOUNCEMENTS_OVERRIDE` env var (JSON) takes precedence over remote announcements.
/// Invalid env var JSON is logged and ignored (falls back to remote).
pub fn resolve_startup(
    remote_announcements: Option<Vec<RemoteAnnouncement>>,
) -> Option<Vec<RemoteAnnouncement>> {
    if let Ok(raw) = std::env::var("FUIGO_ANNOUNCEMENTS_OVERRIDE") {
        match serde_json::from_str::<Vec<RemoteAnnouncement>>(&raw) {
            Ok(list) => return Some(list),
            Err(e) => {
                tracing::warn!(error = %e, "invalid FUIGO_ANNOUNCEMENTS_OVERRIDE JSON; ignoring override");
            }
        }
    }
    remote_announcements
}

#[cfg(all(test, feature = "ts"))]
mod bindings_export {
    use super::*;
    use ts_rs::TS;

    /// Explicitly (re)generate every binding (the export-test pattern).
    /// ts-rs also emits a hidden per-type test from `#[ts(export)]`.
    /// This is the single entry point `generate.sh` drives, failing loudly if any type can't export.
    /// Bindings land in `TS_RS_EXPORT_DIR` (default `bindings/`).
    #[test]
    fn export_all_bindings() {
        let cfg = ts_rs::Config::from_env();
        macro_rules! export {
            ($($t:ty),+ $(,)?) => {$(
                <$t as TS>::export(&cfg).unwrap_or_else(|e| panic!(
                    "exporting {}: {e}", stringify!($t)));
            )+};
        }
        export!(RemoteAnnouncement, AnnouncementCta, AnnouncementsRefreshed);
    }
}

#[cfg(test)]
mod tests {

    /// P72: two pagers recording dismissals at the same time keep each
    /// other's: each writes only the ids it changed, and the file's other ids
    /// stay as they are on disk.
    #[test]
    fn two_writers_hiding_at_once_keep_each_others_dismissals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("announcements.json");
        std::fs::write(&path, r#"{"hidden_ids":["shown-by-b"]}"#).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writer = |tag: &'static str| {
            let (path, barrier) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                let mut hidden = BTreeSet::new();
                barrier.wait();
                for i in 0..30 {
                    let id = format!("{tag}{i}");
                    hidden.insert(id.clone());
                    update_hidden_announcement_ids_at(&path, &hidden, &BTreeSet::from([id])).unwrap();
                }
                if tag == "b" {
                    // b shows one it never had in memory; only that id goes.
                    update_hidden_announcement_ids_at(
                        &path,
                        &hidden,
                        &BTreeSet::from(["shown-by-b".to_owned()]),
                    )
                    .unwrap();
                }
            })
        };
        let a = writer("a");
        let b = writer("b");
        a.join().unwrap();
        b.join().unwrap();
        let ids = parse_hidden_announcement_ids(&std::fs::read_to_string(&path).unwrap());
        for tag in ["a", "b"] {
            for i in 0..30 {
                assert!(ids.contains(&format!("{tag}{i}")), "{tag}{i}");
            }
        }
        assert!(!ids.contains("shown-by-b"));
        assert_eq!(ids.len(), 60);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["announcements.json"]);
    }
    use super::*;

    #[test]
    fn filter_expired_removes_past() {
        let past = RemoteAnnouncement {
            expires_at: Some("2000-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        let future = RemoteAnnouncement {
            expires_at: Some("2100-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        let none = RemoteAnnouncement {
            expires_at: None,
            ..Default::default()
        };

        let filtered = filter_expired(vec![past, future, none]);
        assert_eq!(filtered.len(), 2);
    }

    /// The injected clock decides expiry: the same item is live before its `expires_at` and dropped at/after it (`dt > now` is a strict compare).
    #[test]
    fn filter_expired_at_honors_injected_clock() {
        let item = RemoteAnnouncement {
            expires_at: Some("2030-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        let expiry = DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let before = expiry - chrono::Duration::seconds(1);
        assert_eq!(filter_expired_at(vec![item.clone()], before).len(), 1);
        assert!(filter_expired_at(vec![item.clone()], expiry).is_empty());
        let after = expiry + chrono::Duration::seconds(1);
        assert!(filter_expired_at(vec![item], after).is_empty());
    }

    #[test]
    fn resolve_startup_env_override() {
        // SAFETY: test-only, no concurrent access expected
        unsafe {
            std::env::set_var("FUIGO_ANNOUNCEMENTS_OVERRIDE", r#"[{"id":"test"}]"#);
        }
        let result = resolve_startup(None);
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0].id.as_deref(), Some("test"));
        // SAFETY: test-only
        unsafe {
            std::env::remove_var("FUIGO_ANNOUNCEMENTS_OVERRIDE");
        }
    }

    /// The nested `cta` object is optional and per-field tolerant, matching the parent struct's style.
    /// A partial cta parses instead of failing the whole announcement.
    #[test]
    fn cta_parses_nested_partial_and_absent() {
        let full: RemoteAnnouncement = serde_json::from_str(
            r#"{"id":"p","severity":"promo","cta":{"label":"Get Fuigo Pro","url":"https://example.com/pro","caption":"or use Ctrl+O"}}"#,
        )
        .unwrap();
        let cta = full.cta.as_ref().expect("cta present");
        assert_eq!(cta.label.as_deref(), Some("Get Fuigo Pro"));
        assert_eq!(cta.url.as_deref(), Some("https://example.com/pro"));
        assert_eq!(cta.caption.as_deref(), Some("or use Ctrl+O"));

        let partial: RemoteAnnouncement =
            serde_json::from_str(r#"{"cta":{"label":"only label"}}"#).unwrap();
        assert_eq!(
            partial.cta,
            Some(AnnouncementCta {
                label: Some("only label".into()),
                url: None,
                caption: None,
            })
        );

        let absent: RemoteAnnouncement = serde_json::from_str(r#"{"id":"a"}"#).unwrap();
        assert_eq!(absent.cta, None);
    }

    #[test]
    fn hidden_ids_round_trip() {
        let ids: BTreeSet<String> = ["outage-a".to_string(), "outage-b".to_string()]
            .into_iter()
            .collect();
        let s = serialize_hidden_announcement_ids(&ids).expect("serialize");
        assert_eq!(parse_hidden_announcement_ids(&s), ids);
        assert_eq!(s, r#"{"hidden_ids":["outage-a","outage-b"]}"#);

        let empty = BTreeSet::new();
        let s = serialize_hidden_announcement_ids(&empty).expect("serialize empty");
        assert!(parse_hidden_announcement_ids(&s).is_empty());
    }

    /// The pre-per-ID file shape carried no ids, so it cannot say WHICH announcement was hidden; both values decay to "nothing hidden".
    #[test]
    fn parse_hidden_ids_discards_legacy_bool_shape() {
        assert!(parse_hidden_announcement_ids(r#"{"hidden":true}"#).is_empty());
        assert!(parse_hidden_announcement_ids(r#"{"hidden":false}"#).is_empty());
    }

    #[test]
    fn parse_hidden_ids_tolerates_unknown_fields_and_malformed_input() {
        let got = parse_hidden_announcement_ids(r#"{"hidden_ids":["a"],"future_field":{"x":1}}"#);
        assert_eq!(got, ["a".to_string()].into_iter().collect());

        assert!(parse_hidden_announcement_ids("").is_empty());
        assert!(parse_hidden_announcement_ids("not json").is_empty());
        assert!(parse_hidden_announcement_ids(r#"{"hidden_ids":"oops"}"#).is_empty());
    }

    #[test]
    fn prune_hidden_ids_drops_ids_absent_from_active_list() {
        let active = vec![
            RemoteAnnouncement {
                id: Some("live".into()),
                ..Default::default()
            },
            RemoteAnnouncement {
                id: None,
                title: Some("T".into()),
                message: Some("M".into()),
                ..Default::default()
            },
        ];
        let mut ids: BTreeSet<String> = [
            "live".to_string(),
            "gone".to_string(),
            announcement_hide_key(&active[1]),
        ]
        .into_iter()
        .collect();

        assert!(prune_hidden_announcement_ids(&mut ids, &active));
        assert_eq!(ids.len(), 2);
        assert!(ids.contains("live"));
        assert!(ids.contains(&announcement_hide_key(&active[1])));

        // Second prune with the same list is a no-op.
        assert!(!prune_hidden_announcement_ids(&mut ids, &active));
    }

    #[test]
    fn announcement_hide_key_prefers_id_with_content_fallback() {
        let with_id = RemoteAnnouncement {
            id: Some("  spaced-id  ".into()),
            title: Some("T".into()),
            message: Some("M".into()),
            ..Default::default()
        };
        assert_eq!(announcement_hide_key(&with_id), "spaced-id");

        let blank_id = RemoteAnnouncement {
            id: Some("   ".into()),
            title: Some("T".into()),
            message: Some("M".into()),
            ..Default::default()
        };
        assert_eq!(announcement_hide_key(&blank_id), "content:T\u{1f}M");

        let no_id = RemoteAnnouncement::default();
        assert_eq!(announcement_hide_key(&no_id), "content:\u{1f}");

        // The unprintable separator disambiguates title/message splits.
        let ab_c = RemoteAnnouncement {
            title: Some("a|b".into()),
            message: Some("c".into()),
            ..Default::default()
        };
        let a_bc = RemoteAnnouncement {
            title: Some("a".into()),
            message: Some("b|c".into()),
            ..Default::default()
        };
        assert_ne!(announcement_hide_key(&ab_c), announcement_hide_key(&a_bc));
    }

    #[test]
    fn visible_announcements_filters_empty_message() {
        let a1 = RemoteAnnouncement {
            message: Some("valid".into()),
            ..Default::default()
        };
        let a2 = RemoteAnnouncement {
            message: None,
            ..Default::default()
        };
        let a3 = RemoteAnnouncement {
            message: Some("   ".into()),
            ..Default::default()
        };
        assert_eq!(visible_announcements(&[a1, a2, a3]).len(), 1);
    }
}
