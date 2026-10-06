//! Background `/user` enrichment spawned by `AuthManager::update()`.

use fuigo_extra_ca::dispatch::AsyncRequestBuilderExt as _;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use super::AuthManager;
use super::lock::{Heartbeat, try_lock_auth_file_async};
use crate::auth::manager::AUTH_LOCK_TIMEOUT;
use crate::auth::model::{FuigoAuth, UserInfo, lookup_auth};
use crate::auth::storage::{read_auth_json, write_auth_json};

/// Timeout for the `/user` fetch, shared by the inline (login) and background paths.
const USER_FETCH_TIMEOUT: StdDuration = StdDuration::from_secs(10);

/// Logs `auth update enrichment dropped` if the task is cancelled before it finishes.
/// Normal completion calls `disarm` first, which suppresses the log.
pub(super) struct EnrichmentExitGuard {
    pub(super) started: std::time::Instant,
    pub(super) armed: bool,
}

impl EnrichmentExitGuard {
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for EnrichmentExitGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        fuigo_telemetry::unified_log::warn(
            "auth update enrichment dropped",
            None,
            Some(serde_json::json!({
                "elapsed_ms": self.started.elapsed().as_millis() as u64,
            })),
        );
    }
}

pub(super) fn spawn(manager: Arc<AuthManager>, auth: FuigoAuth) {
    tokio::spawn(async move {
        let mut exit_guard = EnrichmentExitGuard {
            started: std::time::Instant::now(),
            armed: true,
        };
        run_user_info_enrichment(&manager, auth).await;
        exit_guard.disarm();
        #[cfg(test)]
        manager
            .enrichments_finished
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
}

async fn fetch_user_info(manager: &AuthManager, auth: &FuigoAuth, log_label: &str) -> Option<UserInfo> {
    let user_url = format!("{}/user", manager.proxy_base_url);
    // P47: a session credential goes only where the service-endpoint trust class admits `/user` (a static
    // `AuthMode::ApiKey` keeps its own rules). A refusal is logged (with its remedy) and enrichment is skipped.
    if crate::auth::session_delivery::service_session_gate(
        auth,
        &user_url,
        Some(&manager.proxy_base_url),
        "auth_enrichment",
    )
    .is_err()
    {
        fuigo_telemetry::unified_log::warn(
            &format!("{log_label} skipped"),
            None,
            Some(serde_json::json!({ "reason": "destination_refused" })),
        );
        return None;
    }
    let token_header = &manager.fuigo_com_config.token_header;
    let started = std::time::Instant::now();
    let http_client = crate::http::shared_client();
    let response = http_client
        .get(&user_url)
        .timeout(USER_FETCH_TIMEOUT)
        .header("Authorization", format!("Bearer {}", auth.key))
        .header("X-XAI-Token-Auth", token_header.as_str())
        // P43: identity-class header, FluxRouter-operated destinations only.
        .headers(
            fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(&user_url)
                .header_map([("x-fuigo-client-version", fuigo_version::VERSION)]),
        )
        .header(
            crate::http::CLIENT_MODE_HEADER,
            crate::http::process_client_mode(),
        )
        .send_checked()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => match resp.json::<UserInfo>().await {
            Ok(ui) if !ui.user_id.is_empty() => Some(ui),
            Ok(_) => {
                fuigo_telemetry::unified_log::warn(
                    &format!("{log_label} skipped"),
                    None,
                    Some(serde_json::json!({
                        "reason": "empty_user_id",
                        "elapsed_ms": started.elapsed().as_millis() as u64,
                    })),
                );
                None
            }
            Err(e) => {
                fuigo_telemetry::unified_log::warn(
                    &format!("{log_label} failed"),
                    None,
                    Some(serde_json::json!({
                        "reason": "parse",
                        "error": e.to_string(),
                        "elapsed_ms": started.elapsed().as_millis() as u64,
                    })),
                );
                None
            }
        },
        Ok(resp) => {
            fuigo_telemetry::unified_log::warn(
                &format!("{log_label} failed"),
                None,
                Some(serde_json::json!({
                    "reason": "http_status",
                    "http_status": resp.status().as_u16(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                })),
            );
            None
        }
        Err(e) => {
            fuigo_telemetry::unified_log::warn(
                &format!("{log_label} failed"),
                None,
                Some(serde_json::json!({
                    "reason": if e.is_timeout() { "timeout" } else { "transport" },
                    "error": e.to_string(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                })),
            );
            None
        }
    }
}

/// Blocking enrichment at login: merges `/user` fields into `auth` before the first save.
pub(super) async fn enrich_inline(manager: &AuthManager, auth: &mut FuigoAuth) {
    let Some(ui) = fetch_user_info(manager, auth, "auth login enrichment").await else {
        return;
    };
    apply_user_info_enrichment(auth, ui);
}

async fn run_user_info_enrichment(manager: &AuthManager, auth: FuigoAuth) {
    let started = std::time::Instant::now();
    let Some(user_info) = fetch_user_info(manager, &auth, "auth update enrichment").await
    else {
        return;
    };
    let user_elapsed_ms = started.elapsed().as_millis() as u64;
    #[cfg(test)]
    EnrichmentGate::pass(manager, GatePoint::BeforeMerge);

    // Read-modify-write under the file lock. On timeout, skip the write rather than proceed unlocked.
    // An unlocked read-modify-write can silently revert a freshly rotated access or refresh token on disk
    // A rolled-back refresh token later fails with `invalid_grant` and forces a re-login
    // Enrichment is cosmetic; it re-runs on the next refresh
    let lock_started = std::time::Instant::now();
    let lock_guard = try_lock_auth_file_async(&manager.path, AUTH_LOCK_TIMEOUT, Heartbeat::Skip)
        .await
        .into_guard();
    let lock_wait_ms = lock_started.elapsed().as_millis() as u64;
    let Some(_lock_guard) = lock_guard else {
        fuigo_telemetry::unified_log::warn(
            "auth update enrichment skipped",
            None,
            Some(serde_json::json!({
                "reason": "lock_timeout",
                "lock_wait_ms": lock_wait_ms,
            })),
        );
        return;
    };

    // The file lock orders processes (every auth.json writer takes it); the auth-state lock pairs this merge's disk write
    // with its in-memory write (see `auth_state_lock`). Held from the read through the in-memory write below.
    let _state = crate::auth::storage::auth_state_lock();
    let Ok(mut map) = read_auth_json(&manager.path) else {
        fuigo_telemetry::unified_log::warn(
            "auth update enrichment skipped",
            None,
            Some(serde_json::json!({ "reason": "read_disk_failed" })),
        );
        return;
    };
    let Some(mut disk) = lookup_auth(&map, &manager.scope) else {
        fuigo_telemetry::unified_log::info(
            "auth update enrichment skipped",
            None,
            Some(serde_json::json!({ "reason": "no_disk_auth" })),
        );
        return;
    };
    // If the access token or the refresh token on disk differs from the one we wrote, a sibling process rotated tokens since our update()
    // Skip enrichment then, so stale profile data never overwrites the sibling's fresher entry
    // OR, not AND: during a concurrent refresh usually only the key changes while the refresh token stays
    // Team-login transitions (a placeholder user_id becoming real) rotate no tokens, so they still pass this check and get enriched
    if disk.key != auth.key || disk.refresh_token != auth.refresh_token {
        fuigo_telemetry::unified_log::info(
            "auth update enrichment skipped",
            None,
            Some(serde_json::json!({
                "reason": "sibling_rotated",
                "written_key_prefix": fuigo_auth::bearer_fingerprint(&auth.key),
                "disk_key_prefix": fuigo_auth::bearer_fingerprint(&disk.key),
            })),
        );
        return;
    }
    // The same test against memory: a logout, a cleared session, or a newer credential that reached memory but not disk
    // (an `update` whose write failed keeps it in memory) must not be replaced by this older credential's merge.
    let memory_moved = manager.with_inner_read(|current| {
        current.is_none_or(|c| c.key != auth.key || c.refresh_token != auth.refresh_token)
    });
    if memory_moved {
        fuigo_telemetry::unified_log::info(
            "auth update enrichment skipped",
            None,
            Some(serde_json::json!({ "reason": "superseded_in_memory" })),
        );
        return;
    }
    #[cfg(test)]
    EnrichmentGate::pass(manager, GatePoint::BeforeWrite);

    apply_user_info_enrichment(&mut disk, user_info);

    map.insert(manager.scope.clone(), disk.clone());
    let write_started = std::time::Instant::now();
    if let Err(e) = write_auth_json(&manager.path, &map) {
        fuigo_telemetry::unified_log::error(
            "auth update enrichment write failed",
            None,
            Some(serde_json::json!({
                "error": e.to_string(),
                "user_ms": user_elapsed_ms,
                "lock_wait_ms": lock_wait_ms,
                "write_ms": write_started.elapsed().as_millis() as u64,
            })),
        );
        return;
    }
    manager.with_inner_write(|inner| *inner = Some(disk));
    fuigo_telemetry::unified_log::info(
        "auth update enrichment done",
        None,
        Some(serde_json::json!({
            "user_ms": user_elapsed_ms,
            "lock_wait_ms": lock_wait_ms,
            "write_ms": write_started.elapsed().as_millis() as u64,
            "total_ms": started.elapsed().as_millis() as u64,
        })),
    );
}

/// Where a test parks an enrichment: after its `/user` fetch, before it takes any lock; or inside the merge, after
/// every staleness check passed and before it writes (holding the file lock and the auth-state lock).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatePoint {
    BeforeMerge,
    BeforeWrite,
}

/// Test-only: the next enrichment to reach `point` reports arrival on `arrived` and blocks its worker thread until
/// `release` fires (or is dropped). One-shot. Lets a test force an interleaving instead of hoping load produces it.
#[cfg(test)]
pub(crate) struct EnrichmentGate {
    pub(crate) point: GatePoint,
    pub(crate) arrived: std::sync::mpsc::Sender<()>,
    pub(crate) release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
impl EnrichmentGate {
    fn pass(manager: &AuthManager, point: GatePoint) {
        let gate = {
            let mut slot = manager.enrichment_gate.lock();
            if slot.as_ref().is_some_and(|g| g.point == point) {
                slot.take()
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            manager
                .enrichment_parked
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = gate.arrived.send(());
            // Bounded so a test that never releases fails on its own wait instead of hanging this worker forever.
            let _ = gate
                .release
                .recv_timeout(std::time::Duration::from_secs(120));
            manager
                .enrichment_parked
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Merge enrichment fields into disk auth. Does not touch token fields.
pub(super) fn apply_user_info_enrichment(disk: &mut FuigoAuth, user_info: UserInfo) {
    disk.user_id = user_info.user_id;
    disk.first_name = user_info.first_name.or(disk.first_name.take());
    disk.last_name = user_info.last_name.or(disk.last_name.take());
    disk.profile_image_asset_id = user_info
        .profile_image_asset_id
        .or(disk.profile_image_asset_id.take());
    disk.principal_type = user_info.principal_type.or(disk.principal_type.take());
    disk.principal_id = user_info.principal_id.or(disk.principal_id.take());
    disk.team_id = user_info.team_id.or(disk.team_id.take());
    disk.team_name = user_info.team_name.or(disk.team_name.take());
    disk.team_role = user_info.team_role.or(disk.team_role.take());
    disk.organization_id = user_info.organization_id.or(disk.organization_id.take());
    disk.organization_name = user_info
        .organization_name
        .or(disk.organization_name.take());
    disk.organization_role = user_info
        .organization_role
        .or(disk.organization_role.take());
    disk.user_blocked_reason = user_info
        .user_blocked_reason
        .or(disk.user_blocked_reason.take());
    if let Some(reasons) = user_info.team_blocked_reasons {
        disk.team_blocked_reasons = reasons;
    }
    if let Some(opt_out) = user_info.coding_data_retention_opt_out {
        disk.coding_data_retention_opt_out = opt_out;
    }
    if let Some(ref email) = user_info.email
        && !email.is_empty()
    {
        disk.email = user_info.email;
    }
}

#[cfg(test)]
mod p43_identity_tests {
    /// P43 hostile: the `/user` enrichment fetch to a proxy that is not FluxRouter-operated
    /// carries no client version.
    #[tokio::test(flavor = "current_thread")]
    async fn user_enrichment_sends_no_identity_to_a_non_fluxrouter_proxy() {
        let (base, seen, handle) =
            crate::remote::identity_tests::spawn_recording_mock("{}").await;
        let dir = tempfile::tempdir().unwrap();
        let manager =
            super::AuthManager::new(dir.path(), crate::auth::FuigoComConfig::default())
                .with_proxy_base_url(&base);
        // A static API key: P47's service-endpoint gate leaves it alone, so the request reaches the loopback mock
        // and this test still observes what P43 decides about identity.
        let auth = crate::auth::FuigoAuth {
            key: "token".into(),
            auth_mode: crate::auth::AuthMode::ApiKey,
            ..crate::auth::FuigoAuth::test_default()
        };
        let _ = super::fetch_user_info(&manager, &auth, "p43").await;
        handle.abort();
        crate::remote::identity_tests::assert_no_identity(&seen, "auth_enrichment");
    }
}
