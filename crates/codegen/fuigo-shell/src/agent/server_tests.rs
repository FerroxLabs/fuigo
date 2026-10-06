//! Slot-lifecycle tests for the persistent agent boot path.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;

use super::{AgentSlot, BootSlotGuard, fail_boot, reclaim_abandoned_boot};

fn booting(boot_id: u64) -> (tokio::sync::watch::Sender<()>, AgentSlot) {
    let (boot_tx, boot_rx) = tokio::sync::watch::channel(());
    (
        boot_tx,
        AgentSlot::Booting {
            boot_id,
            rx: boot_rx,
        },
    )
}

fn boot_rx(slot: &AgentSlot) -> tokio::sync::watch::Receiver<()> {
    match slot {
        AgentSlot::Booting { rx, .. } => rx.clone(),
        _ => panic!("expected Booting"),
    }
}

#[tokio::test]
async fn dropped_boot_sender_reclaims_booting_slot() {
    let (boot_tx, slot_val) = booting(1);
    let slot = tokio::sync::Mutex::new(slot_val);
    let rx = boot_rx(&*slot.lock().await);
    drop(boot_tx);

    timeout(Duration::from_secs(1), reclaim_abandoned_boot(&slot, rx, 1))
        .await
        .expect("reclaim must not wait after the sender is gone");
    assert!(matches!(*slot.lock().await, AgentSlot::Down));
}

#[tokio::test]
async fn boot_guard_drop_resets_booting_and_wakes_waiter() {
    let (boot_tx, slot_val) = booting(1);
    let slot = Arc::new(tokio::sync::Mutex::new(slot_val));
    let rx = boot_rx(&*slot.lock().await);

    let waiter = {
        let slot = Arc::clone(&slot);
        tokio::spawn(async move { reclaim_abandoned_boot(&slot, rx, 1).await })
    };

    drop(BootSlotGuard::new(&slot, boot_tx, 1));
    timeout(Duration::from_secs(1), waiter)
        .await
        .expect("waiter must observe the dropped boot sender")
        .expect("waiter task");
    assert!(matches!(*slot.lock().await, AgentSlot::Down));
}

#[tokio::test]
async fn boot_guard_does_not_clobber_up_after_notify() {
    let (boot_tx, slot_val) = booting(1);
    let (conn_tx, _conn_rx) = mpsc::unbounded_channel();
    let slot = tokio::sync::Mutex::new(slot_val);
    let mut guard = BootSlotGuard::new(&slot, boot_tx, 1);
    *slot.lock().await = AgentSlot::Up(conn_tx);
    guard.notify_waiters();
    drop(guard);
    assert!(matches!(*slot.lock().await, AgentSlot::Up(_)));
}

#[tokio::test]
async fn waiter_keeps_up_when_sender_drops_after_success() {
    let (boot_tx, slot_val) = booting(1);
    let (conn_tx, _conn_rx) = mpsc::unbounded_channel();
    let slot = tokio::sync::Mutex::new(slot_val);
    let rx = boot_rx(&*slot.lock().await);
    *slot.lock().await = AgentSlot::Up(conn_tx);
    drop(boot_tx);

    timeout(Duration::from_secs(1), reclaim_abandoned_boot(&slot, rx, 1))
        .await
        .expect("reclaim must return");
    assert!(matches!(*slot.lock().await, AgentSlot::Up(_)));
}

#[tokio::test]
async fn stale_reclaim_does_not_clobber_newer_boot() {
    let (old_tx, old) = booting(1);
    let slot = tokio::sync::Mutex::new(old);
    let old_rx = boot_rx(&*slot.lock().await);
    let (_new_tx, new) = booting(2);
    *slot.lock().await = new;
    drop(old_tx);

    timeout(
        Duration::from_secs(1),
        reclaim_abandoned_boot(&slot, old_rx, 1),
    )
    .await
    .expect("stale reclaim must return");
    assert!(matches!(
        *slot.lock().await,
        AgentSlot::Booting { boot_id: 2, .. }
    ));
}

#[tokio::test]
async fn stale_guard_drop_does_not_clobber_newer_boot() {
    let (old_tx, old) = booting(1);
    let slot = tokio::sync::Mutex::new(old);
    let guard = BootSlotGuard::new(&slot, old_tx, 1);
    let (_new_tx, new) = booting(2);
    *slot.lock().await = new;
    drop(guard);
    assert!(matches!(
        *slot.lock().await,
        AgentSlot::Booting { boot_id: 2, .. }
    ));
}

#[tokio::test]
async fn stale_fail_boot_does_not_clobber_newer_boot() {
    let (_old_tx, old) = booting(1);
    let slot = tokio::sync::Mutex::new(old);
    let (_new_tx, new) = booting(2);
    *slot.lock().await = new;
    let _ = fail_boot(&slot, 1).await;
    assert!(matches!(
        *slot.lock().await,
        AgentSlot::Booting { boot_id: 2, .. }
    ));
}

#[tokio::test]
async fn matching_fail_boot_resets_slot() {
    let (_tx, val) = booting(3);
    let slot = tokio::sync::Mutex::new(val);
    let _ = fail_boot(&slot, 3).await;
    assert!(matches!(*slot.lock().await, AgentSlot::Down));
}

/// P82: the `agent serve` secret check. The right secret is admitted from the header or the query, and nothing else
/// is: not a prefix of it, not a longer value, not another case, not a header with a wrong secret beside a right query
/// (the header decides, as before), and with an EMPTY server secret nobody, not even an empty `Bearer ` or
/// `?server-key=`.
#[test]
fn p82_agent_serve_admits_only_the_secret() {
    use super::{WsQueryParams, validate_auth};
    use axum::http::{HeaderMap, HeaderValue};
    let header = |value: &str| {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_str(value).unwrap());
        headers
    };
    let query = |key: &str| WsQueryParams { server_key: Some(key.to_owned()) };
    let none = WsQueryParams::default();
    let secret = "s3cret-0123456789";
    assert!(validate_auth(&header(&format!("Bearer {secret}")), &none, secret));
    assert!(validate_auth(&HeaderMap::new(), &query(secret), secret));
    for wrong in [
        "",
        "s",
        "s3cret-012345678",
        "s3cret-01234567890",
        "S3CRET-0123456789",
        "x3cret-0123456789",
        " s3cret-0123456789",
        "s3cret-0123456789 ",
        "s3cret-0123456789\t",
    ] {
        assert!(!validate_auth(&header(&format!("Bearer {wrong}")), &none, secret), "header {wrong:?}");
        assert!(!validate_auth(&HeaderMap::new(), &query(wrong), secret), "query {wrong:?}");
    }
    assert!(!validate_auth(&header("Bearer wrong"), &query(secret), secret), "the header decides");
    // A header that is not a bearer header does not decide: the query still can, as before.
    assert!(validate_auth(&header("Basic czNjcmV0"), &query(secret), secret), "a non-bearer header falls back to the query");
    assert!(!validate_auth(&header("Basic czNjcmV0"), &query("wrong"), secret));
    assert!(!validate_auth(&header(secret), &none, secret), "not a bearer header");
    assert!(!validate_auth(&HeaderMap::new(), &none, secret));
    for presented in ["", "x"] {
        assert!(!validate_auth(&header(&format!("Bearer {presented}")), &none, ""), "empty server secret, header {presented:?}");
        assert!(!validate_auth(&HeaderMap::new(), &query(presented), ""), "empty server secret, query {presented:?}");
    }
}

/// P82 source pin: the secret is compared only through `secret_matches`, which hashes both sides and compares every
/// byte (no `==` on the secret, which stops at the first differing byte).
#[test]
fn p82_agent_serve_compares_the_secret_in_constant_time() {
    let src = include_str!("server.rs");
    let prod = src.split("\n#[cfg(test)]").next().unwrap();
    let flat = prod.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(flat.matches("== expected_secret").count(), 0);
    assert_eq!(flat.matches("expected_secret ==").count(), 0);
    assert_eq!(flat.matches("secret_matches(").count(), 3, "definition + header + query");
    for pinned in [
        "return secret_matches(token, expected_secret);",
        "return secret_matches(key, expected_secret);",
        // Both whole functions, so no comparison can be added before the hashes, in the helper or its callers.
        "fn validate_auth(headers: &HeaderMap, query: &WsQueryParams, expected_secret: &str) -> bool { if let Some(token) = \
         headers .get(\"authorization\") .and_then(|v| v.to_str().ok()) .and_then(|v| v.strip_prefix(\"Bearer \")) { \
         return secret_matches(token, expected_secret); } if let Some(ref key) = query.server_key { \
         return secret_matches(key, expected_secret); } false }",
        "fn secret_matches(presented: &str, expected_secret: &str) -> bool { use sha2::{Digest as _, Sha256}; \
         if expected_secret.is_empty() { return false; } let presented = Sha256::digest(presented.as_bytes()); \
         let expected = Sha256::digest(expected_secret.as_bytes()); \
         presented.iter().zip(expected.iter()).fold(0u8, |differ, (a, b)| differ | (a ^ b)) == 0 }",
    ] {
        assert!(flat.contains(pinned), "{pinned}");
    }
}
