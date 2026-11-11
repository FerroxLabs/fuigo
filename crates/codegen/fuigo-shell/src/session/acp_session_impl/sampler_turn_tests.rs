use fuigo_sampling_types::{SearchDateBound, ToolOverrides, WebSearchOptions, XSearchOptions};

use super::{
    CLASSIFIER_REQUEST_TOKEN_RESERVE, LengthSalvageAction, LengthSalvageStreak,
    MAX_OUTPUT_TOKEN_LIMIT_RETRIES, classifier_request_fits_context, resolve_configured_cutoff,
};

fn x_cut(to: &str) -> XSearchOptions {
    XSearchOptions {
        date_bound: Some(SearchDateBound::new(None, Some(to.into())).unwrap()),
    }
}

/// When every sample ends with finish reason Length while tools are active, the turn salvages up to the cap and then fails.
/// The reminder is injected only on the first salvage.
#[test]
fn length_salvage_streak_proceeds_to_the_cap_then_exhausts() {
    let mut streak = LengthSalvageStreak::default();
    for n in 1..=MAX_OUTPUT_TOKEN_LIMIT_RETRIES {
        match streak.on_sample(true) {
            LengthSalvageAction::Proceed { inject_reminder } => {
                assert_eq!(
                    inject_reminder,
                    n == 1,
                    "reminder only on the first salvage"
                );
            }
            other => panic!("salvage {n} within the cap must proceed, got {other:?}"),
        }
    }
    assert!(matches!(
        streak.on_sample(true),
        LengthSalvageAction::Exhausted
    ));
}

/// A non-Length (or tool-less) sample resets the streak: a later salvage starts a fresh streak and re-injects the reminder.
#[test]
fn length_salvage_streak_resets_on_non_length_sample() {
    let mut streak = LengthSalvageStreak::default();
    for _ in 0..MAX_OUTPUT_TOKEN_LIMIT_RETRIES {
        let _ = streak.on_sample(true);
    }
    assert!(matches!(
        streak.on_sample(false),
        LengthSalvageAction::NotSalvage
    ));
    assert!(matches!(
        streak.on_sample(true),
        LengthSalvageAction::Proceed {
            inject_reminder: true
        }
    ));
}

#[test]
fn classifier_request_bound_enforces_its_reserve_with_saturating_arithmetic() {
    let window = 12_000 + CLASSIFIER_REQUEST_TOKEN_RESERVE;
    for (input, context_window, expected) in [
        (12_000, window, true),
        (12_001, window, false),
        (u64::MAX, u64::MAX, false),
    ] {
        assert_eq!(
            classifier_request_fits_context(input, context_window),
            expected
        );
    }
}

#[test]
fn seed_cutoff_is_inherited_without_a_per_turn_update() {
    let seed = ToolOverrides {
        x_search: Some(x_cut("2020-01-01")),
        web_search: None,
    };
    assert_eq!(resolve_configured_cutoff(Some(seed.clone()), None), seed);
}

#[test]
fn non_empty_base_cutoff_wins_per_tool_and_an_empty_one_reverts_to_the_seed() {
    let seed = ToolOverrides {
        x_search: Some(x_cut("2020-01-01")),
        web_search: Some(WebSearchOptions {
            allowed_domains: Some(vec!["x.com".into()]),
            excluded_domains: None,
        }),
    };
    let base = ToolOverrides {
        x_search: Some(x_cut("2019-06-01")),
        web_search: Some(WebSearchOptions {
            allowed_domains: Some(vec![]),
            excluded_domains: None,
        }),
    };
    let got = resolve_configured_cutoff(Some(seed.clone()), Some(&base));
    assert_eq!(got.x_search, Some(x_cut("2019-06-01")));
    assert_eq!(got.web_search, seed.web_search);
}

#[test]
fn inherited_cutoff_agrees_with_the_wire_echo_so_the_two_implementations_cannot_drift() {
    use fuigo_sampling_types::{HostedTool, apply_tool_overrides};
    let web = WebSearchOptions {
        allowed_domains: Some(vec!["x.com".into()]),
        excluded_domains: None,
    };
    let cases = [
        (
            Some(ToolOverrides {
                x_search: Some(x_cut("2020-01-01")),
                web_search: None,
            }),
            None,
        ),
        (
            Some(ToolOverrides {
                x_search: Some(x_cut("2020-01-01")),
                web_search: Some(web.clone()),
            }),
            Some(ToolOverrides {
                x_search: Some(x_cut("2019-06-01")),
                web_search: None,
            }),
        ),
        (
            None,
            Some(ToolOverrides {
                x_search: Some(x_cut("2018-01-01")),
                web_search: Some(web.clone()),
            }),
        ),
    ];
    for (seed, base) in cases {
        let mut tools = vec![
            HostedTool::WebSearch { options: None },
            HostedTool::XSearch { options: None },
        ];
        apply_tool_overrides(&mut tools, seed.as_ref());
        let wire_echo = apply_tool_overrides(&mut tools, base.as_ref());
        let inherited = resolve_configured_cutoff(seed.clone(), base.as_ref());
        assert_eq!(wire_echo, inherited, "seed={seed:?} base={base:?}");
    }
}

#[cfg(test)]
mod subagent_sampling_gate_tests {
    use super::super::super::support::create_test_actor;
    use super::super::acquire_subagent_sampling_permit;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Semaphore;

    #[derive(Default)]
    struct ConcurrencyProbe {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
    }

    impl ConcurrencyProbe {
        fn enter(&self) {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        }
        fn leave(&self) {
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn subagent_submits_never_exceed_cap_and_excess_queues() {
        const CAP: usize = 3;
        const TURNS: usize = 12;
        let semaphore = Arc::new(Semaphore::new(CAP));
        let probe = Arc::new(ConcurrencyProbe::default());
        let ran = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..TURNS {
            let gate = Some(semaphore.clone());
            let probe = probe.clone();
            let ran = ran.clone();
            handles.push(tokio::spawn(async move {
                let permit = acquire_subagent_sampling_permit(&gate).await;
                assert!(permit.is_some(), "a subagent turn must receive a permit");
                probe.enter();
                tokio::time::sleep(Duration::from_millis(20)).await;
                probe.leave();
                ran.fetch_add(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            ran.load(Ordering::SeqCst),
            TURNS,
            "every queued turn ran (queued, not errored)"
        );
        assert!(
            probe.max_in_flight.load(Ordering::SeqCst) <= CAP,
            "in-flight subagent submits exceeded the cap: {} > {CAP}",
            probe.max_in_flight.load(Ordering::SeqCst),
        );
    }

    #[tokio::test]
    async fn cancelled_waiter_releases_without_deadlock() {
        let semaphore = Arc::new(Semaphore::new(1));
        let gate = Some(semaphore.clone());
        let held = acquire_subagent_sampling_permit(&gate).await;
        assert!(held.is_some());

        let waiter = tokio::spawn({
            let gate = gate.clone();
            async move {
                let _permit = acquire_subagent_sampling_permit(&gate).await;
                std::future::pending::<()>().await;
            }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(
            semaphore.available_permits(),
            0,
            "slot stays held while the second turn queues"
        );
        waiter.abort();
        let _ = waiter.await;

        drop(held);
        let next = tokio::time::timeout(
            Duration::from_millis(200),
            acquire_subagent_sampling_permit(&gate),
        )
        .await
        .expect("a permit must be free once the held one is released");
        assert!(next.is_some(), "the cancelled waiter did not leak the slot");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn submit_holds_permit_for_subagent_not_main() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let saturated = Arc::new(Semaphore::new(1));
                let _held = saturated.clone().acquire_owned().await.unwrap();

                let (gw_tx, _gw_rx) = tokio::sync::mpsc::unbounded_channel();
                let (p_tx, _p_rx) = tokio::sync::mpsc::unbounded_channel();
                let mut subagent = create_test_actor(0, 200_000, 80, gw_tx, p_tx).await;
                subagent.sampling_gate = Some(saturated.clone());
                let subagent = Arc::new(subagent);

                let queued = tokio::time::timeout(
                    Duration::from_millis(150),
                    subagent.submit_turn_request(Default::default()),
                )
                .await;
                assert!(
                    queued.is_err(),
                    "a subagent submit must queue behind the drained gate, never reaching the sampler"
                );

                let (gw_tx, _gw_rx) = tokio::sync::mpsc::unbounded_channel();
                let (p_tx, _p_rx) = tokio::sync::mpsc::unbounded_channel();
                let main = create_test_actor(0, 200_000, 80, gw_tx, p_tx).await;
                assert!(main.sampling_gate.is_none());
                let main = Arc::new(main);

                let ran = tokio::time::timeout(
                    Duration::from_millis(150),
                    main.submit_turn_request(Default::default()),
                )
                .await;
                assert!(
                    ran.is_ok(),
                    "the main session must reach the sampler even while the gate is drained"
                );
                assert!(
                    main.turn_stream_drained.lock().is_empty(),
                    "a result with no queued terminal event must release request ownership before returning"
                );
            })
            .await;
    }
}

// A2.1 W13/W14/W16: changing a model or compacting the body cannot reopen a
// terminal prompt. These are real HTTP dispatch attempts through the production gate.
#[tokio::test]
async fn busyloop_terminal_gate_blocks_every_late_model_dispatch() {
    use fuigo_sampler::{ApiBackend, SamplerConfig, SamplingClient};
    use fuigo_sampling_types::refusal::{PromptSM, PromptState};
    use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
    let server = MockInferenceServer::start().await.unwrap();
    let sid = format!("busyloop-{}", uuid::Uuid::new_v4());
    let prompt = std::sync::Arc::new(std::sync::Mutex::new(PromptSM::new(false)));
    super::bind_refusal_prompt(&sid, &prompt);
    let cfg = |side, model: &str| SamplerConfig {
        base_url: server.url(),
        flux_base_url: Some(server.url()),
        model: model.into(),
        api_key: Some("fixture-dummy".into()),
        api_backend: ApiBackend::Responses,
        dispatch_gate: Some(std::sync::Arc::new(super::ParkGate::new(sid.clone(), if side { crate::session::acp_session::CallRole::Side } else { crate::session::acp_session::CallRole::Main }, None))),
        ..Default::default()
    };
    server.enqueue_response(
        "/v1/responses",
        ScriptedResponse::json(402, serde_json::json!({"error":{"message":"refused"}})),
    );
    let client = SamplingClient::new(cfg(false, "flux-auto")).unwrap();
    assert!(
        client
            .conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new())
            .await
            .is_err()
    );
    assert_eq!(prompt.lock().unwrap().state, PromptState::Terminal);
    assert_eq!(server.request_count(), 1);
    for (kind, side, model) in [
        ("sampler_retry", false, "flux-auto"),
        ("provider_4c", false, "other"),
        ("transient_4d", false, "flux-auto"),
        ("compact", false, "flux-auto"),
        ("resume", false, "flux-auto"),
        ("side", true, "flux-fast"),
    ] {
        let client = SamplingClient::new(cfg(side, model)).unwrap();
        let mut req = fuigo_sampling_types::ConversationRequest::new();
        req.items.push(fuigo_sampling_types::ConversationItem::User(
            fuigo_sampling_types::UserItem {
                content: vec![fuigo_sampling_types::ContentPart::Text {
                    text: std::sync::Arc::from(format!("different body {kind}")),
                }],
                ..Default::default()
            },
        ));
        assert!(
            client.conversation_stream_responses(req).await.is_err(),
            "{kind}"
        );
        assert_eq!(
            server.request_count(),
            1,
            "{kind} dispatched after terminal"
        );
    }
}
#[tokio::test]
async fn busyloop_side_refusal_never_terminates_main_prompt() {
    use fuigo_sampling_types::refusal::{PromptSM, PromptState};
    use fuigo_test_support::{MockInferenceServer, ScriptedResponse};
    let server = MockInferenceServer::start().await.unwrap();
    let sid = format!("busyloop-side-{}", uuid::Uuid::new_v4());
    let prompt = std::sync::Arc::new(std::sync::Mutex::new(PromptSM::new(false)));
    super::bind_refusal_prompt(&sid, &prompt);
    for side in [true, false] {
        server.enqueue_response(
            "/v1/responses",
            ScriptedResponse::json(
                402,
                serde_json::json!({"error":{"message":"credit balance is exhausted"}}),
            ),
        );
        let client = fuigo_sampler::SamplingClient::new(fuigo_sampler::SamplerConfig {
            base_url: server.url(),
            flux_base_url: Some(server.url()),
            model: if side { "flux-fast" } else { "flux-auto" }.into(),
            api_key: Some("fixture-dummy".into()),
            api_backend: fuigo_sampler::ApiBackend::Responses,
            dispatch_gate: Some(std::sync::Arc::new(super::ParkGate::new(sid.clone(), if side { crate::session::acp_session::CallRole::Side } else { crate::session::acp_session::CallRole::Main }, None))),
            ..Default::default()
        })
        .unwrap();
        assert!(
            client
                .conversation_stream_responses(fuigo_sampling_types::ConversationRequest::new())
                .await
                .is_err()
        );
        assert_eq!(
            prompt.lock().unwrap().state,
            if side {
                PromptState::Open
            } else {
                PromptState::Terminal
            }
        );
    }
    assert_eq!(server.request_count(), 2);
}

#[test]
fn r2_park_gate_literals_have_one_constructor() {
    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() { scan(&p, hits); }
            else if p.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&p).unwrap();
                let pattern = regex::Regex::new(concat!(r"(?:\b|::)", "ParkGate", r"\s*\{")).unwrap();
                for m in pattern.find_iter(&text) {
                    let prefix = &text[..m.start()];
                    let line = prefix.rsplit('\n').next().unwrap();
                    if line.contains("struct ") || line.contains("impl ") { continue; }
                    if p.file_name().unwrap() == "sampler_turn.rs" {
                        let implementation = text.find("impl ParkGate {").unwrap();
                        let constructor = implementation + text[implementation..].find("fn new(").unwrap();
                        let body = constructor + text[constructor..].find('{').unwrap();
                        let mut depth = 0;
                        let end = text[body..].char_indices().find_map(|(offset, ch)| {
                            if ch == '{' { depth += 1; }
                            if ch == '}' { depth -= 1; }
                            (depth == 0).then_some(body + offset)
                        }).unwrap();
                        assert!((body..end).contains(&m.start()), "ParkGate literal outside its call-role constructor");
                    }
                    hits.push(p.file_name().unwrap().to_string_lossy().to_string());
                }
            }
        }
    }
    let mut hits = Vec::new();
    scan(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut hits);
    assert_eq!(hits, vec!["sampler_turn.rs"], "only the call-role constructor may build the dispatch gate");
}

/// Production text of a source file: everything before the first `#[cfg(test)]` that gates an INLINE `mod x { .. }`.
/// A `#[cfg(test)] use` / `fn` earlier in the file does not end production code, and neither does a `mod x;`
/// declaration (its file is skipped by the test-file name filter, and code after the declaration is production).
fn production_text(text: &str) -> &str {
    let lines: Vec<&str> = text.lines().collect();
    let mut offsets = Vec::with_capacity(lines.len());
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        offsets.push(at);
        at += line.len();
    }
    let inline_mod = regex::Regex::new(r"^(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{").unwrap();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() != "#[cfg(test)]" { continue; }
        let item = lines[i + 1..].iter().map(|l| l.trim())
            .find(|l| !l.is_empty() && !l.starts_with("#[") && !l.starts_with("//"));
        if item.is_some_and(|l| inline_mod.is_match(l)) { return &text[..offsets[i]]; }
    }
    text
}

/// `(model-endpoint literals seen, 1-based lines of those not preceded by a `check_open` in the same function)`.
fn ungated_model_endpoint_sites(text: &str) -> (usize, Vec<usize>) {
    let endpoint = regex::Regex::new(r#""[^"]*/(responses|chat/completions|messages)\b[^"]*""#).unwrap();
    let function = regex::Regex::new(r"^\s*(pub(\([^)]*\))?\s+)?(const\s+)?(async\s+)?(unsafe\s+)?fn\s").unwrap();
    let lines: Vec<&str> = production_text(text).lines().collect();
    let (mut seen, mut offenders) = (0, Vec::new());
    for (i, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with("//") || !endpoint.is_match(line) { continue; }
        seen += 1;
        let start = (0..=i).rev().find(|&j| function.is_match(lines[j])).unwrap_or(0);
        let end = (i + 1..lines.len()).find(|&j| function.is_match(lines[j])).unwrap_or(lines.len());
        if !lines[start..end].iter().any(|l| l.contains("check_open")) { offenders.push(i + 1); }
    }
    (seen, offenders)
}

/// Root-cause guard for the web-search escape: production code outside the sampler that builds a model-endpoint URL
/// (`/responses`, `/chat/completions`, `/messages`) must consult the dispatch gate (`check_open`) in the same function.
#[test]
fn r3_model_endpoint_dispatch_sites_consult_the_gate() {
    // Not a dispatch: a path allowlist for credential recipients.
    const ALLOWED_FILES: &[&str] = &[
        "fuigo-extra-ca/src/subscription.rs",
        // Only counts the requests a test server received.
        "fuigo-pager/src/app/leader_cluster/mod.rs",
    ];
    fn scan(dir: &std::path::Path, root: &std::path::Path, offenders: &mut Vec<String>, seen: &mut usize) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                if matches!(name.as_str(), "tests" | "examples" | "benches" | "target" | "fuigo-sampler" | "fuigo-test-support" | "fuigo-test-utils") || name.contains("harness") { continue; }
                scan(&p, root, offenders, seen);
            } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") && !name.ends_with("_test.rs") && name != "tests.rs" {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
                if ALLOWED_FILES.iter().any(|a| rel.ends_with(a)) { continue; }
                let (n, lines) = ungated_model_endpoint_sites(&std::fs::read_to_string(&p).unwrap());
                *seen += n;
                offenders.extend(lines.into_iter().map(|l| format!("{rel}:{l}")));
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").canonicalize().unwrap();
    let mut offenders = Vec::new();
    let mut seen = 0;
    scan(&crates, &crates, &mut offenders, &mut seen);
    assert!(seen >= 2, "the scan must see the web search request sites; saw {seen}");
    assert!(offenders.is_empty(), "model-endpoint request built without a dispatch-gate check in the same function: {offenders:?}");
}

/// The guard must catch what a lazier scan misses: a planted ungated request after an early `#[cfg(test)] use`,
/// and one inside a `pub(in path) fn`; and it must still cut test modules and accept a gated request.
#[test]
fn r3_dispatch_guard_catches_planted_ungated_requests() {
    let after_cfg_test_use = "#[cfg(test)]\nuse std::fmt;\nfn send(c: &C) {\n    let u = format!(\"{}/responses\", b);\n    c.post(&u);\n}\n";
    assert_eq!(ungated_model_endpoint_sites(after_cfg_test_use), (1, vec![4]));
    let restricted = "pub(in crate::x) fn send(c: &C) {\n    let u = format!(\"{}/chat/completions\", b);\n    c.post(&u);\n}\n";
    assert_eq!(ungated_model_endpoint_sites(restricted), (1, vec![2]));
    let super_async = "pub(super) async fn send(c: &C) {\n    let u = \"https://h/v1/messages\";\n}\nconst fn other() {}\n";
    assert_eq!(ungated_model_endpoint_sites(super_async), (1, vec![2]));
    let declared_mod = "#[cfg(test)]\nmod tests;\nfn send(c: &C) { let u = \"/responses\"; }\n";
    assert_eq!(ungated_model_endpoint_sites(declared_mod), (1, vec![3]));
    let gated = "fn send(g: &G) {\n    g.check_open()?;\n    let u = \"/responses\";\n}\n#[cfg(test)]\nmod tests {\n    fn t() { let u = \"/responses\"; }\n}\n";
    assert_eq!(ungated_model_endpoint_sites(gated), (1, vec![]));
}
