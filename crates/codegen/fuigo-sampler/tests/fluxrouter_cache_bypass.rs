//! FluxRouter serves byte-identical requests from its exact-match response cache, so one empty model reply to an
//! agent turn was replayed to every retry. Fuigo opts out with the body field
//! `"cache": {"no-cache": true, "no-store": true}` on FluxRouter-bound requests only: strict providers (OpenAI,
//! Anthropic, xAI) reject unknown body fields with a 400.
//!
//! Fresh-process tests. The child points real `SamplingClient`s (all six dispatches) and a `SamplerActor` turn per
//! wire format at plain-HTTP base URLs; an environment proxy delivers every request to the parent's mock, which
//! records the body each destination actually received. The base URL host is the only variable.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri, header::HOST};
use axum::response::{IntoResponse, Response, sse::Sse};
use fuigo_sampler::{
    ApiBackend, RequestId, RetryPolicy, SamplerActor, SamplerConfig, SamplingClient, SamplingEvent,
};
use fuigo_sampling_types::{ContentPart, ConversationItem, ConversationRequest, UserItem};
use fuigo_test_support::{TestSandbox, sse};
use futures_util::stream;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const CHILD: &str = "FUIGO_CACHE_BYPASS_CHILD";
const BASES: &str = "FUIGO_CACHE_BYPASS_BASES";
const CHILD_DONE: &str = "cache-bypass-child-drove-every-base";
/// Six `SamplingClient` dispatches plus one actor turn per wire format.
const REQUESTS_PER_BASE: usize = 9;
const WIRE_PATHS: [&str; 3] = ["/chat/completions", "/responses", "/messages"];

#[derive(Clone, Debug)]
struct Captured {
    /// The URL the client addressed, rebuilt from the proxied request.
    url: String,
    body: Value,
}

fn request() -> ConversationRequest {
    ConversationRequest {
        items: vec![ConversationItem::User(UserItem {
            content: vec![ContentPart::Text {
                text: Arc::from("reply DONE"),
            }],
            ..Default::default()
        })],
        ..Default::default()
    }
}

/// Valid streams, so actor turns end without retrying; unary calls only need the request to leave.
fn reply(path: &str, streaming: bool) -> Response {
    if !streaming {
        return (StatusCode::OK, "{}").into_response();
    }
    let events = if path.ends_with("/responses") {
        sse::responses_api_events("DONE", "test-model")
    } else if path.ends_with("/messages") {
        sse::messages_api_events("DONE", "test-model", "end_turn")
    } else {
        sse::chat_completion_events("DONE", "test-model")
    };
    Sse::new(stream::iter(
        events.into_iter().map(Ok::<_, std::convert::Infallible>),
    ))
    .into_response()
}

async fn drive(base: &str) {
    let config = SamplerConfig {
        api_key: Some("test-key".into()),
        base_url: base.into(),
        model: "test-model".into(),
        max_retries: Some(0),
        idle_timeout_secs: Some(10),
        ..SamplerConfig::default()
    };
    let client = SamplingClient::new(config.clone()).expect("client builds");
    // Response shapes are irrelevant here; only the sent bodies are checked.
    let _ = client.conversation(request()).await;
    let _ = client.conversation_stream(request()).await;
    let _ = client.conversation_responses(request()).await;
    let _ = client.conversation_stream_responses(request()).await;
    let _ = client.conversation_messages(request()).await;
    let _ = client.conversation_stream_messages(request()).await;
    for api_backend in [
        ApiBackend::ChatCompletions,
        ApiBackend::Responses,
        ApiBackend::Messages,
    ] {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let handle = SamplerActor::spawn(
            SamplerConfig {
                api_backend: api_backend.clone(),
                ..config.clone()
            },
            RetryPolicy::default(),
            event_tx,
        );
        handle.submit(RequestId::from("cache-bypass-turn"), request());
        tokio::time::timeout(Duration::from_secs(60), async {
            while let Some(event) = event_rx.recv().await {
                if matches!(
                    event,
                    SamplingEvent::Completed { .. } | SamplingEvent::Failed { .. }
                ) {
                    return;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{base} {api_backend:?} actor turn did not finish"));
    }
}

async fn child() {
    let bases = std::env::var(BASES).expect("bases");
    for base in bases.split(',') {
        drive(base).await;
    }
    println!("{CHILD_DONE}");
}

/// Owns the child's isolated paths for as long as the child runs, and the variables it is given.
struct ChildEnv {
    _sandbox: TestSandbox,
    vars: Vec<(OsString, OsString)>,
}

/// The environment the recording child is spawned with.
///
/// The child starts from a cleared environment so the parent's own proxy and endpoint settings cannot
/// decide which base URL gets the bypass. Cleared cannot mean empty: a Windows process cannot be created
/// without `PATH`, `SystemRoot` and `ComSpec`, so the platform essentials come from `TestSandbox`, the
/// repo's hermetic child-environment owner, and this test's proxy wiring is layered on top of them.
fn child_env(proxy_url: &str, bases: &[&str]) -> ChildEnv {
    let mut sandbox = TestSandbox::new();
    sandbox.extend_env([
        (CHILD, "1".to_owned()),
        (BASES, bases.join(",")),
        ("HTTP_PROXY", proxy_url.to_owned()),
        ("HTTPS_PROXY", proxy_url.to_owned()),
        ("ALL_PROXY", proxy_url.to_owned()),
        // The sandbox exempts loopback from proxying; here every destination must reach the mock.
        ("NO_PROXY", String::new()),
        ("no_proxy", String::new()),
    ]);
    let vars = sandbox.env();
    ChildEnv {
        _sandbox: sandbox,
        vars,
    }
}

/// Run `test` in a fresh child whose environment proxy is a recording mock, and return what the mock received.
async fn run_child(test: &str, bases: &[&str]) -> Vec<Captured> {
    let log: Arc<Mutex<Vec<Captured>>> = Arc::default();
    let sink = log.clone();
    let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let sink = sink.clone();
        async move {
            // A proxied request carries the absolute URL; fall back to Host for origin-form.
            let authority = uri
                .authority()
                .map(|a| a.to_string())
                .or_else(|| {
                    headers
                        .get(HOST)
                        .and_then(|h| h.to_str().ok())
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let streaming = body["stream"] == json!(true);
            let path = uri.path().to_owned();
            sink.lock().unwrap().push(Captured {
                url: format!("http://{authority}{path}"),
                body,
            });
            reply(&path, streaming)
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let child = child_env(&proxy_url, bases);
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env_clear()
        .envs(child.vars.iter().map(|(key, value)| (key, value)))
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    server.abort();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(CHILD_DONE),
        "child failed\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    log.lock().unwrap().clone()
}

/// The requests addressed under `base`, after asserting every dispatch and wire format reached the mock.
fn requests_for<'a>(captured: &'a [Captured], base: &str) -> Vec<&'a Captured> {
    let prefix = format!(
        "{}/",
        reqwest::Url::parse(base)
            .expect("base parses")
            .as_str()
            .trim_end_matches('/')
    );
    let hits: Vec<&Captured> = captured
        .iter()
        .filter(|c| c.url.starts_with(&prefix))
        .collect();
    assert!(
        hits.len() >= REQUESTS_PER_BASE,
        "{base}: expected at least {REQUESTS_PER_BASE} requests, saw {:?}",
        hits.iter().map(|c| &c.url).collect::<Vec<_>>()
    );
    for path in WIRE_PATHS {
        assert!(
            hits.iter().any(|c| c.url.ends_with(path)),
            "{base}: no {path} request reached the mock"
        );
    }
    hits
}

fn keys(body: &Value) -> Vec<&str> {
    body.as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fluxrouter_bound_requests_carry_the_cache_bypass() {
    if std::env::var_os(CHILD).is_some() {
        return child().await;
    }
    let bases = [
        "http://api.fluxrouter.ai/v1",
        "http://api.fluxrouter.ai/anthropic",
        "http://API.FluxRouter.ai.:8080/v1",
    ];
    let captured = run_child("fluxrouter_bound_requests_carry_the_cache_bypass", &bases).await;
    for base in bases {
        for sent in requests_for(&captured, base) {
            assert_eq!(
                sent.body.get("cache"),
                Some(&json!({"no-cache": true, "no-store": true})),
                "{} was sent without FluxRouter's cache bypass; body keys {:?}",
                sent.url,
                keys(&sent.body)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_endpoints_never_receive_the_cache_bypass() {
    if std::env::var_os(CHILD).is_some() {
        return child().await;
    }
    let bases = [
        "http://api.openai.com/v1",
        "http://api.anthropic.com/v1",
        "http://gateway.example.com/v1",
        "http://fluxrouter.ai/v1",
        "http://api.fluxrouter.ai.evil.example/v1",
    ];
    let captured = run_child("other_endpoints_never_receive_the_cache_bypass", &bases).await;
    for base in bases {
        for sent in requests_for(&captured, base) {
            assert!(
                sent.body.get("cache").is_none(),
                "{} must not receive FluxRouter's cache bypass; body keys {:?}",
                sent.url,
                keys(&sent.body)
            );
        }
    }
}

/// Workspace root: this crate sits at `crates/codegen/fuigo-sampler`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Variables a child process needs from its parent to start at all on this platform.
#[cfg(windows)]
const PLATFORM_ESSENTIALS: &[&str] = &["PATH", "PATHEXT", "SystemRoot", "ComSpec"];
#[cfg(not(windows))]
const PLATFORM_ESSENTIALS: &[&str] = &["PATH"];

/// The child is spawned from a cleared environment so the parent's own proxy and endpoint settings cannot
/// decide the result. Cleared must not mean empty: a Windows child with no `PATH`, `SystemRoot` or
/// `ComSpec` cannot be created, so this test would never run there.
#[test]
fn the_child_environment_keeps_the_platform_variables_a_spawn_needs() {
    let child = child_env("http://127.0.0.1:1", &["http://api.fluxrouter.ai/v1"]);
    let vars: BTreeMap<&OsStr, &OsStr> = child
        .vars
        .iter()
        .map(|(key, value)| (key.as_os_str(), value.as_os_str()))
        .collect();
    for key in PLATFORM_ESSENTIALS {
        if std::env::var_os(key).is_none() {
            continue;
        }
        assert!(
            vars.contains_key(OsStr::new(key)),
            "the child environment drops {key}, which a spawn on this platform needs; \
             it has {:?}",
            vars.keys().collect::<Vec<_>>()
        );
    }
    // The isolation the clear buys is still the point: this test's own wiring must win.
    assert_eq!(vars.get(OsStr::new(CHILD)), Some(&OsStr::new("1")));
    assert_eq!(vars.get(OsStr::new("NO_PROXY")), Some(&OsStr::new("")));
    assert_eq!(
        vars.get(OsStr::new("HTTPS_PROXY")),
        Some(&OsStr::new("http://127.0.0.1:1"))
    );
}

/// The cargo invocation that runs this file in CI.
const CI_CALL: &str = "-p fuigo-sampler --test fluxrouter_cache_bypass";
/// What a CI call site must say about itself, on the line directly above the run.
const CI_GATE_MARK: &str = "# fluxrouter cache bypass gate:";

/// The bypass is only as good as the run that proves it, and a run is only as good as the gate it sits
/// behind. Pin both: the call site, so deleting it fails here instead of silently leaving the regression
/// uncovered, and a comment directly above it naming WHICH gate that call site is, so the coverage a
/// reader assumes is the coverage that exists.
///
/// Today there is exactly one call site and it is the RELEASE gate: `release.yml` runs on a `v*` tag push
/// and on `workflow_dispatch`, so this file proves the bypass at release time, not on a pull request.
/// There is no PR-level call site to pin because no PR-level workflow runs fuigo-sampler tests at all --
/// `dispatch-policy.yml` is this repo's only `pull_request` workflow and it runs fuigo-extra-ca,
/// ptyctl-cli, gcloud-auth, gcloud-metadata and fuigo-file-utils tests. When a PR-level run is added,
/// this test makes it label its own gate the same way.
#[test]
fn ci_runs_this_integration_test_and_every_call_site_names_its_gate() {
    let dir = repo_root().join(".github/workflows");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("workflow directory entry").path())
        // GitHub only reads workflows sitting directly in this directory; anything else is not one.
        .filter(|path| path.is_file())
        .collect();
    entries.sort();
    let mut sites: Vec<String> = Vec::new();
    for path in entries {
        let workflow = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let lines: Vec<&str> = workflow.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            if !line.contains(CI_CALL) {
                continue;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            // The comment block directly above the run, innermost line first.
            let above: Vec<&str> = lines[..at]
                .iter()
                .rev()
                .map(|line| line.trim())
                .take_while(|line| line.starts_with('#'))
                .collect();
            assert!(
                above.iter().any(|line| line.starts_with(CI_GATE_MARK)),
                "{name}:{} runs this test but no comment above it begins {CI_GATE_MARK:?}, so nothing \
                 says which gate this run is; the comment block reads {above:?}",
                at + 1
            );
            sites.push(name.into_owned());
        }
    }
    assert!(
        sites.iter().any(|name| name == "release.yml"),
        "no release-gate job runs `cargo test {CI_CALL}`, so nothing proves the FluxRouter cache bypass \
         is still sent at release time; call sites found: {sites:?}"
    );
}

/// The cache opt-out paragraph of the user guide, as the single Markdown line it is written on.
fn cache_paragraph() -> String {
    let path = repo_root().join("crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md");
    let guide =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    guide
        .lines()
        .find(|line| line.contains(r#""cache": {"no-cache": true, "no-store": true}"#))
        .expect("the user guide describes the cache opt-out")
        .to_owned()
}

/// Sentences of the paragraph. A surface and the verdict it is given have to share one.
fn sentences(paragraph: &str) -> Vec<&str> {
    paragraph.split(". ").collect()
}

/// Does `text` name `surface` as a path in its own right? `/v1/messages` also occurs inside
/// `/anthropic/v1/messages`, and those are two different mounts with two different names.
fn names_surface(text: &str, surface: &str) -> bool {
    text.match_indices(surface).any(|(at, _)| {
        text[..at]
            .chars()
            .next_back()
            .is_none_or(|previous| !previous.is_ascii_alphanumeric() && previous != '/')
    })
}

/// Flux Router honours the body `cache` field on Chat Completions only: its Responses surface and both of
/// its Anthropic Messages mounts -- the bare `/v1/messages` that the default base URL reaches with
/// `api_backend = "messages"`, and the prefixed `/anthropic/v1/messages` -- rebuild the upstream request
/// from a fixed field list and drop it. The guide has to pair each surface with ITS OWN verdict: asserting
/// that the words appear somewhere in the paragraph would pass just as happily on a rewrite that swapped
/// which surface honours the field, which is the one error a reader could not detect.
#[test]
fn the_user_guide_pairs_each_flux_router_surface_with_its_own_verdict() {
    let paragraph = cache_paragraph();
    let sentences = sentences(&paragraph);
    for (surface, verdict, contrary) in [
        ("/v1/chat/completions", "honour", "drop"),
        ("/v1/responses", "drop", "honour"),
        ("/v1/messages", "drop", "honour"),
        ("/anthropic/v1/messages", "drop", "honour"),
    ] {
        let naming: Vec<&&str> = sentences
            .iter()
            .filter(|sentence| names_surface(sentence, surface))
            .collect();
        assert!(
            !naming.is_empty(),
            "the cache opt-out paragraph never names the {surface} surface:\n{paragraph}"
        );
        for sentence in naming {
            assert!(
                sentence.contains(verdict),
                "the sentence naming {surface} never says what Flux Router does with the field there \
                 ({verdict:?}):\n{sentence}"
            );
            assert!(
                !sentence.contains(contrary),
                "the sentence naming {surface} gives it the opposite verdict ({contrary:?}):\n{sentence}"
            );
        }
    }
}

/// `api.fluxrouter.ai` keeping agent traffic out of its own cache is a property of a DEPLOYMENT, not of
/// the protocol: it becomes true when the router fix ships, which is why that deploy happens before Fuigo
/// 1.0.18 publishes, and it is never a promise about a Flux Router the reader runs themselves. This guide
/// ships inside the binary and is read long after today, so the sentence has to be pinned in time and
/// scoped to that host rather than written as a standing present-tense fact.
#[test]
fn the_user_guide_pins_the_router_cache_claim_to_a_deployment() {
    let paragraph = cache_paragraph();
    let claim = sentences(&paragraph)
        .into_iter()
        .find(|sentence| sentence.contains("agent traffic"))
        .unwrap_or_else(|| {
            panic!(
                "the paragraph never says why the opt-out is safe on the surfaces that drop the \
                 field:\n{paragraph}"
            )
        });
    assert!(
        claim.contains("api.fluxrouter.ai"),
        "the router-cache claim does not say which Flux Router it is about, so it reads as a promise \
         about every router a user might point at:\n{claim}"
    );
    assert!(
        ["deployment", "deployed", "release"]
            .iter()
            .any(|when| claim.contains(when)),
        "the router-cache claim is stated as a standing fact instead of being tied to the router release \
         that makes it true:\n{claim}"
    );
    for scope in ["self-hosted", "older"] {
        assert!(
            paragraph.contains(scope),
            "the paragraph never says {scope:?}, so it does not tell the reader that another Flux Router \
             may still replay a retry:\n{paragraph}"
        );
    }
}
