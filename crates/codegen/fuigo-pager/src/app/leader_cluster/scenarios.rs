//! Scenario tests driving [`PagerLeaderCluster`] (the harness lives in `mod.rs`).
//! New multi-client scenarios land here so the harness and its consumers grow independently.

use super::*;

const T1: &str = "CLUSTER_SENTINEL_T1";
const T2: &str = "CLUSTER_SENTINEL_T2";

/// Two clients share one session: the driver's turn streams into the attached viewer live, and replay renders exactly once.
/// The driver and viewer roles flip for the next turn.
/// This is an in-process port of the `leader_two_clients_shared_session` PTY case.
#[test]
#[ignore = "leader-cluster: needs single-process isolation (process-global env + fuigo_home OnceLock in the shared lib test binary); run: cargo test -p fuigo-pager --lib -- app::leader_cluster --ignored --test-threads=1"]
#[serial_test::serial(FUIGO_HOME)]
fn two_clients_share_session_and_stream_both_ways() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let mut cluster = PagerLeaderCluster::start().await;
        let mut a = cluster.client("cluster-a", false).await;

        cluster.server.set_response(format!("{T1} first turn."));
        let sid = a.new_session().await;
        a.run_turn("go", T1).await;

        // The viewer attaches and replays the transcript exactly once
        let mut b = cluster.client("cluster-b", false).await;
        b.load_session(&sid).await;
        b.pump_until("replay reaches viewer", move |app| {
            app.agents
                .values()
                .any(|agent| agent_message_text(agent).contains(T1))
        })
        .await;
        assert_eq!(
            occurrences(&agent_message_text(b.agent_for_session(&sid)), T1),
            1,
            "replayed turn must render exactly once in the viewer"
        );

        // Turn 2, driven from the driver, streams into the viewer live
        cluster.server.set_response(format!("{T2} second turn."));
        a.act(Action::SendPrompt("again".to_string()));
        pump_clients_until(&mut [&mut a, &mut b], "turn 2 fans out", |clients| {
            clients.iter().all(|c| {
                c.app
                    .agents
                    .values()
                    .any(|agent| agent_message_text(agent).contains(T2))
            })
        })
        .await;
        assert_eq!(
            occurrences(&agent_message_text(b.agent_for_session(&sid)), T2),
            1,
            "live turn must render exactly once in the viewer"
        );
        assert_eq!(
            occurrences(&agent_message_text(a.agent_for_session(&sid)), T2),
            1,
            "live turn must render exactly once in the driver"
        );

        a.sever();
        b.sever();
    });
}

/// N-client fan-out: one driver, three viewers.
/// Live turns broadcast to every subscriber exactly once.
/// Each viewer's attach replay is unicast; it never duplicates into the already-attached clients.
#[test]
#[ignore = "leader-cluster: needs single-process isolation (process-global env + fuigo_home OnceLock in the shared lib test binary); run: cargo test -p fuigo-pager --lib -- app::leader_cluster --ignored --test-threads=1"]
#[serial_test::serial(FUIGO_HOME)]
fn n_client_fan_out_without_replay_duplication() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let mut cluster = PagerLeaderCluster::start().await;
        let mut driver = cluster.client("cluster-driver", false).await;

        cluster.server.set_response(format!("{T1} fan-out seed."));
        let sid = driver.new_session().await;
        driver.run_turn("go", T1).await;

        let mut viewers = Vec::new();
        for i in 0..3 {
            let mut viewer = cluster.client(&format!("cluster-viewer-{i}"), false).await;
            viewer.load_session(&sid).await;
            viewer
                .pump_until("viewer replay lands", move |app| {
                    app.agents
                        .values()
                        .any(|agent| agent_message_text(agent).contains(T1))
                })
                .await;
            assert_eq!(
                occurrences(&agent_message_text(viewer.agent_for_session(&sid)), T1),
                1,
                "viewer {i} must replay the transcript exactly once"
            );
            viewers.push(viewer);
        }
        // The driver must NOT have received any copy of the unicast replays.
        driver.pump_once();
        assert_eq!(
            occurrences(&agent_message_text(driver.agent_for_session(&sid)), T1),
            1,
            "attach replays must be unicast — never duplicated into the driver"
        );

        // A live turn reaches all four clients exactly once each.
        cluster.server.set_response(format!("{T2} fan-out live."));
        driver.act(Action::SendPrompt("again".to_string()));
        let mut all: Vec<&mut ClusterClient> = Vec::new();
        all.push(&mut driver);
        for viewer in viewers.iter_mut() {
            all.push(viewer);
        }
        pump_clients_until(&mut all, "live turn fans out to all", |clients| {
            clients.iter().all(|c| {
                c.app
                    .agents
                    .values()
                    .any(|agent| agent_message_text(agent).contains(T2))
            })
        })
        .await;
        for (i, client) in all.iter().enumerate() {
            assert_eq!(
                occurrences(&agent_message_text(client.agent_for_session(&sid)), T2),
                1,
                "client {i} must see the live turn exactly once"
            );
        }
        // Release the &mut borrows before consuming the clients.
        drop(all);

        for viewer in viewers {
            viewer.sever();
        }
        driver.sever();
    });
}

/// Reattach after the driver disconnects: a completed turn round-trips through the durable log.
/// The fresh client replays it exactly once, lands Idle, and no inference request is re-driven.
/// This is an in-process port of `leader_reattach_completion_roundtrips_durable_log`.
#[test]
#[ignore = "leader-cluster: needs single-process isolation (process-global env + fuigo_home OnceLock in the shared lib test binary); run: cargo test -p fuigo-pager --lib -- app::leader_cluster --ignored --test-threads=1"]
#[serial_test::serial(FUIGO_HOME)]
fn reattach_completion_roundtrips_durable_log() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let mut cluster = PagerLeaderCluster::start().await;
        let mut a = cluster.client("cluster-a", false).await;

        cluster.server.set_response(format!("{T1} durable turn."));
        let sid = a.new_session().await;
        a.run_turn("go", T1).await;

        // A keep-alive viewer keeps the session resident across A's exit (parity with the PTY case; the in-process server also survives)
        let mut keep = cluster.client("cluster-keepalive", false).await;
        keep.load_session(&sid).await;

        // The completed turn is durable on disk before the reattach
        // The write is async relative to the PromptResponse, so poll briefly (the PTY port does the same via wait_for_turn_completed)
        let durable_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let recorded = find_session_updates_file(&sid).is_some_and(|updates| {
                std::fs::read_to_string(&updates)
                    .unwrap_or_default()
                    .contains("turn_completed")
            });
            if recorded {
                break;
            }
            assert!(
                tokio::time::Instant::now() < durable_deadline,
                "durable log never recorded the turn terminal for {sid}"
            );
            tokio::time::sleep(PUMP_TICK).await;
        }

        let inference_before = cluster.inference_request_count();
        a.sever();

        let mut c = cluster.client("cluster-reattach", false).await;
        c.load_session(&sid).await;
        c.pump_until("reattach replay lands", move |app| {
            app.agents
                .values()
                .any(|agent| agent_message_text(agent).contains(T1))
        })
        .await;

        let view = c.agent_for_session(&sid);
        assert_eq!(
            occurrences(&agent_message_text(view), T1),
            1,
            "reattach must replay the completed transcript exactly once"
        );
        assert!(
            matches!(view.session.state, AgentState::Idle),
            "a completed turn must reattach Idle, not stuck waiting"
        );
        assert_eq!(
            cluster.inference_request_count(),
            inference_before,
            "reattach must replay from the durable log, not re-drive a turn"
        );

        keep.sever();
        c.sever();
    });
}

/// Reconnect one client to the respawned leader and reload its session by hand, the way the event loop's reconnect arm does.
/// Waits for the bridge to adopt the new generation, re-initialises (and re-authenticates once per generation, as the agent is shared),
/// then `begin_session_reload`, `session/load`, `finish_session_reload`.
/// `plan_reconnect_load` is event_loop-private, so the session id, cwd and meta (including the reconnect cursor) are derived inline.
async fn reconnect_and_reload(
    cluster: &mut PagerLeaderCluster,
    client: &mut ClusterClient,
    sid: &str,
) {
    let mut status_rx = client.status_rx.clone().expect("reconnecting client");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if matches!(
            *status_rx.borrow_and_update(),
            ConnectionStatus::Connected { generation } if generation >= 1
        ) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "bridge never reconnected to the respawned leader"
        );
        client.pump_once();
        tokio::time::sleep(PUMP_TICK).await;
    }

    let _init: acp::InitializeResponse = bounded(
        "reconnect re-initialize",
        acp_send(
            acp::InitializeRequest::new(acp::ProtocolVersion::V1).client_capabilities(
                acp::ClientCapabilities::new()
                    .fs(acp::FileSystemCapabilities::new())
                    .terminal(false),
            ),
            &client.app.acp_tx,
        ),
    )
    .await
    .expect("re-initialize after reconnect");
    if !cluster.authenticated {
        let _: acp::AuthenticateResponse = bounded(
            "reconnect re-authenticate",
            acp_send(
                acp::AuthenticateRequest::new(acp::AuthMethodId::new("fuigo.api_key"))
                    .meta(serde_json::json!({ "headless": true }).as_object().cloned()),
                &client.app.acp_tx,
            ),
        )
        .await
        .expect("re-authenticate after reconnect");
        cluster.authenticated = true;
    }

    let (agent_id, load_sid, load_cwd, load_meta) = {
        let (id, agent) = client
            .app
            .agents
            .iter()
            .find(|(_, agent)| {
                agent
                    .session
                    .session_id
                    .as_ref()
                    .is_some_and(|s| s.0.as_ref() == sid)
            })
            .expect("reconnecting tab exists");
        let cwd = if agent.session.cwd.as_os_str().is_empty() {
            client.app.cwd.clone()
        } else {
            agent.session.cwd.clone()
        };
        let mut meta = serde_json::json!({ "yoloMode": false, "autoMode": false });
        let cursor = agent
            .last_seen_event_id
            .clone()
            .expect("a client that saw a turn holds a reconnect cursor");
        meta["cursor"] = serde_json::Value::String(cursor);
        (*id, agent.session.session_id.clone().unwrap(), cwd, meta)
    };
    client
        .app
        .agents
        .get_mut(&agent_id)
        .unwrap()
        .begin_session_reload(1);
    let load = bounded(
        "reconnect session/load",
        acp_send(
            acp::LoadSessionRequest::new(load_sid, load_cwd)
                .mcp_servers(vec![])
                .meta(load_meta.as_object().cloned()),
            &client.app.acp_tx,
        ),
    )
    .await;
    let ok = load.is_ok();

    // With a cursor the leader replays only the events AFTER it, and nothing follows the last completed turn, so there is no replay to wait for.
    // (Waiting for the old text to reappear in the fresh state never completes; the transcript comes back from the stash on finalize.)
    // Whatever the leader did send precedes the load response on the wire, so pump until the client has been quiet for a few ticks before finalizing.
    let deadline = tokio::time::Instant::now() + TURN_BUDGET;
    let mut quiet_ticks = 0;
    while quiet_ticks < 5 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "client never went quiet after session/load"
        );
        quiet_ticks = if client.pump_once() {
            0
        } else {
            quiet_ticks + 1
        };
        tokio::time::sleep(PUMP_TICK).await;
    }
    client
        .app
        .agents
        .get_mut(&agent_id)
        .unwrap()
        .finish_session_reload(1, ok);
    assert!(ok, "reconnect session/load failed: {:?}", load.err());
}

/// Kill the leader and let every bridge reconnect (real `LeaderReconnector`, socket pinned) to ONE respawned leader.
/// Then reload each client by hand: history renders exactly once on every client, no turn is re-driven, and a new turn fans out to both.
/// A driver and a viewer share the session, so this covers the all-clients case, not just the client that ran the turn.
#[test]
#[ignore = "leader-cluster: needs single-process isolation (process-global env + fuigo_home OnceLock in the shared lib test binary); run: cargo test -p fuigo-pager --lib -- app::leader_cluster --ignored --test-threads=1"]
#[serial_test::serial(FUIGO_HOME)]
fn leader_kill_reconnect_reloads_without_duplicating_history() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&rt, async {
        let mut cluster = PagerLeaderCluster::start().await;
        let mut a = cluster.client("cluster-reconnect-driver", true).await;

        cluster.server.set_response(format!("{T1} pre-crash turn."));
        let sid = a.new_session().await;
        a.run_turn("go", T1).await;

        let mut b = cluster.client("cluster-reconnect-viewer", true).await;
        b.load_session(&sid).await;
        b.pump_until("replay reaches viewer", move |app| {
            app.agents
                .values()
                .any(|agent| agent_message_text(agent).contains(T1))
        })
        .await;
        let inference_before_crash = cluster.inference_request_count();

        // Kill the leader generation, respawn at the same path; both bridges' reconnectors adopt the one new in-process server
        cluster.kill_leader().await;
        cluster.respawn_leader().await;

        reconnect_and_reload(&mut cluster, &mut a, &sid).await;
        reconnect_and_reload(&mut cluster, &mut b, &sid).await;

        for (name, client) in [("driver", &a), ("viewer", &b)] {
            assert_eq!(
                occurrences(&agent_message_text(client.agent_for_session(&sid)), T1),
                1,
                "reconnect reload must not duplicate history on the {name}"
            );
        }
        assert_eq!(
            cluster.inference_request_count(),
            inference_before_crash,
            "reconnect must reload from the durable log, not re-drive a turn"
        );

        // The reconnected generation serves new turns, and one leader fans them out to every client.
        cluster
            .server
            .set_response(format!("{T2} post-crash turn."));
        a.act(Action::SendPrompt("after crash".to_string()));
        pump_clients_until(
            &mut [&mut a, &mut b],
            "post-crash turn fans out",
            |clients| {
                clients.iter().all(|c| {
                    c.app
                        .agents
                        .values()
                        .any(|agent| agent_message_text(agent).contains(T2))
                })
            },
        )
        .await;
        for (name, client) in [("driver", &a), ("viewer", &b)] {
            let text = agent_message_text(client.agent_for_session(&sid));
            assert_eq!(
                occurrences(&text, T1),
                1,
                "history stays single on the {name}"
            );
            assert_eq!(
                occurrences(&text, T2),
                1,
                "post-crash turn renders once on the {name}"
            );
        }

        a.sever();
        b.sever();
    });
}

/// Locate `<fuigo_home>/sessions/<enc-cwd>/<sid>/updates.jsonl` without the (internal) cwd encoder.
/// Scan one level of cwd dirs, the same approach as session_load_perf's `locate_session_dir`.
fn find_session_updates_file(sid: &str) -> Option<PathBuf> {
    let sessions = effective_fuigo_home().join("sessions");
    for entry in std::fs::read_dir(&sessions).ok()?.flatten() {
        let candidate = entry.path().join(sid).join("updates.jsonl");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
