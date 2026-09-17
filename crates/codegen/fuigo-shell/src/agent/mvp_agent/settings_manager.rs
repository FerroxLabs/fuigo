//! Single-flight post-auth settings fetch. Concurrent callers for the same credential
//! identity share one leader fetch (followers receive the leader's outcome); a sequential
//! trigger re-fetches; a dropped leader makes one follower lead a fresh fetch; repeated
//! leader drops end in `None` rather than a fabricated `Retry` (which would open the
//! fail-closed OTEL gate on cancellation churn).

use std::cell::RefCell;
use std::future::Future;

use tokio::sync::watch;

use crate::auth::FuigoAuth;
use crate::remote::SettingsFetch;

#[derive(Clone, PartialEq, Eq)]
struct CredentialIdentity {
    user_id: String,
    key: String,
}

impl From<&FuigoAuth> for CredentialIdentity {
    fn from(auth: &FuigoAuth) -> Self {
        Self {
            user_id: auth.user_id.clone(),
            key: auth.key.clone(),
        }
    }
}

#[derive(Default)]
struct State {
    epoch: u64,
    identity: Option<CredentialIdentity>,
    in_flight: Option<watch::Receiver<Option<SettingsFetch>>>,
}

impl State {
    fn reset_to(&mut self, identity: CredentialIdentity) {
        self.epoch += 1;
        self.identity = Some(identity);
        self.in_flight = None;
    }
}

#[derive(Default)]
pub(super) struct SettingsManager {
    state: RefCell<State>,
}

enum Plan {
    Join(watch::Receiver<Option<SettingsFetch>>),
    Lead(watch::Sender<Option<SettingsFetch>>),
}

impl SettingsManager {
    const MAX_DROPPED_LEADER_REATTEMPTS: u32 = 3;

    pub(super) async fn fetch<F, Fut>(&self, auth: &FuigoAuth, leader: F) -> Option<SettingsFetch>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = SettingsFetch>,
    {
        let identity = CredentialIdentity::from(auth);
        let mut leader = Some(leader);
        let mut dropped_leader_reattempts = 0u32;
        loop {
            let (plan, my_epoch) = {
                let mut st = self.state.borrow_mut();
                if st.identity.as_ref() != Some(&identity) {
                    st.reset_to(identity.clone());
                }
                let my_epoch = st.epoch;
                let plan = if let Some(rx) = st.in_flight.as_ref() {
                    Plan::Join(rx.clone())
                } else {
                    let (tx, rx) = watch::channel(None);
                    st.in_flight = Some(rx);
                    Plan::Lead(tx)
                };
                (plan, my_epoch)
            };
            match plan {
                Plan::Join(mut rx) => {
                    let published = loop {
                        if let Some(outcome) = rx.borrow_and_update().clone() {
                            break Some(outcome);
                        }
                        if rx.changed().await.is_err() {
                            break None;
                        }
                    };
                    match published {
                        Some(outcome) => return Some(outcome),
                        None => {
                            dropped_leader_reattempts += 1;
                            if dropped_leader_reattempts > Self::MAX_DROPPED_LEADER_REATTEMPTS {
                                return None;
                            }
                        }
                    }
                }
                Plan::Lead(tx) => {
                    let mut guard = LeaderGuard {
                        manager: self,
                        epoch: my_epoch,
                        published: false,
                    };
                    let run = leader.take().expect("leader closure consumed at most once");
                    let outcome = run().await;
                    {
                        let mut st = self.state.borrow_mut();
                        if st.epoch == my_epoch {
                            st.in_flight = None;
                        }
                    }
                    guard.published = true;
                    let _ = tx.send(Some(outcome.clone()));
                    return Some(outcome);
                }
            }
        }
    }
}

/// Frees the lead slot when a leader is dropped before publishing, so a parked follower
/// re-plans (and leads) instead of waiting forever.
struct LeaderGuard<'a> {
    manager: &'a SettingsManager,
    epoch: u64,
    published: bool,
}

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let mut st = self.manager.state.borrow_mut();
        if st.epoch == self.epoch {
            st.in_flight = None;
        }
    }
}
