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

/// The line indices of the workflow's LIVE call sites for this test file. A YAML comment runs nothing,
/// so a commented-out line is not a call site -- and commenting a step out is the usual way one gets
/// disabled.
fn call_sites(workflow: &str) -> Vec<usize> {
    workflow
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(CI_CALL) && !line.trim_start().starts_with('#'))
        .map(|(at, _)| at)
        .collect()
}

/// The bypass is only as good as the run that proves it, and a run is only as good as the gate it sits
/// behind. Pin both: the call site, so deleting it fails here instead of silently leaving the regression
/// uncovered, and a comment directly above it naming WHICH gate that call site is, so the coverage a
/// reader assumes is the coverage that exists.
///
/// Today there is exactly one call site and it is the RELEASE gate: `release.yml` runs on a `v*` tag push
/// and on `workflow_dispatch`, so this FILE proves the bypass at release time, not on a pull request.
/// There is no PR-level call site to pin because no PR-level workflow runs fuigo-sampler tests at all --
/// `dispatch-policy.yml` is this repo's only `pull_request` workflow and it runs fuigo-extra-ca,
/// ptyctl-cli, gcloud-auth, gcloud-metadata and fuigo-file-utils tests. The host gate this file exercises
/// at the wire level IS covered on pull requests by the `fuigo_extra_ca::fluxrouter` unit tests, which
/// that dispatch-policy run includes. When a PR-level run of this file is added, this test makes it label
/// its own gate the same way.
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
        for at in call_sites(&workflow) {
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

/// Commenting a step out is how a CI step actually gets disabled -- far more often than deleting it.
/// A YAML comment is not a call site: a run block whose only mention of this test file is commented out
/// runs nothing, so counting it would let the guard above report coverage that does not exist (and let a
/// commented line satisfy the gate-comment requirement as well, since it begins with `#`).
#[test]
fn a_commented_out_ci_call_site_is_not_coverage() {
    let live = format!(
        "      run: |\n        # fluxrouter cache bypass gate: release only.\n        cargo test --locked {CI_CALL} -- --test-threads=1\n"
    );
    assert_eq!(
        call_sites(&live).len(),
        1,
        "a live run line is a call site:\n{live}"
    );

    let disabled = format!(
        "      run: |\n        # fluxrouter cache bypass gate: release only.\n        # DISABLED (flaky): cargo test --locked {CI_CALL} -- --test-threads=1\n"
    );
    assert!(
        call_sites(&disabled).is_empty(),
        "a commented-out run line counts as a call site, so this workflow would be reported as running \
         the cache-bypass proof while it runs nothing:\n{disabled}"
    );

    // Indentation is normal in a YAML run block; the comment marker is what matters.
    let indented = format!("            #cargo test --locked {CI_CALL}\n");
    assert!(
        call_sites(&indented).is_empty(),
        "an indented comment counts as a call site:\n{indented}"
    );
}

/// The literal the cache opt-out paragraph is found by.
const CACHE_FIELD: &str = r#""cache": {"no-cache": true, "no-store": true}"#;

/// The cache opt-out paragraph of `markdown`, as one string: the blank-line-delimited block containing
/// the cache field, with its lines rejoined. Every paragraph in the guide is one long line today, but a
/// hard wrap is an ordinary edit that changes nothing a reader sees and must not break the assertions
/// below, which read whole sentences.
///
/// Every block is rejoined BEFORE the field is looked for, because the wrap can land inside the
/// backticked literal itself -- Markdown gives a code span no protection from a reflow. Searching the
/// raw block first would miss that paragraph entirely and report a reflow as a missing opt-out.
fn cache_paragraph_of(markdown: &str) -> String {
    markdown
        .split("\n\n")
        .map(|block| {
            block
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<&str>>()
                .join(" ")
        })
        .find(|block| block.contains(CACHE_FIELD))
        .expect("the user guide describes the cache opt-out")
}

/// The cache opt-out paragraph of the user guide.
fn cache_paragraph() -> String {
    let path = repo_root().join("crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md");
    let guide =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    cache_paragraph_of(&guide)
}

/// Sentences of the paragraph. A surface and the verdict it is given have to share one.
fn sentences(paragraph: &str) -> Vec<&str> {
    paragraph.split(". ").collect()
}

/// The cache opt-out paragraph, pinned verbatim.
///
/// Seven consecutive review rounds each corrected a different false claim in this one paragraph, and
/// every heuristic guard written to stop the next one was gamed, misfired, or both. The round-5
/// negation check accepted "... and batch speech-to-text posts `/v1/audio/transcriptions`, with no
/// JSON body field left out" -- prose asserting the exact opposite of what the guard existed to
/// allow -- while rejecting ordinary true denials such as "those paths are excluded". A matcher can
/// test vocabulary; it cannot tell a true claim from a false one. Only a reader can.
///
/// So the paragraph is pinned as golden text. Being brittle to every edit is the POINT: it stops
/// prose drifting past a clever matcher and forces a human to re-read the source instead.
const CACHE_PARAGRAPH: &str = r#"Fuigo opts its Flux Router chat and search requests — not everything it sends to Flux Router — out of Flux Router's response cache with the body field `"cache": {"no-cache": true, "no-store": true}`. Which requests carry it is a rule, not a roster: a request carries the field when it is built on the session's sampling client and the resolved base URL is a Flux Router host (`api.fluxrouter.ai`). That covers every model turn on all three wire formats and, by the same mechanism, any side call that rebuilds the session's sampling configuration — session titles and conversation compaction are examples of those, not the whole set. The web search tool posts through its own HTTP client rather than that one and applies the same host rule itself, so its searches carry the field too. A subscription transport and every other provider receive nothing extra, because a strict provider rejects an unknown body field with a 400. Fuigo's media and audio paths are built by different clients that never add the field, so `/v1/images/generations`, `/v1/images/edits`, `/v1/videos/generations` and `/v1/audio/transcriptions` go without it even on a default install, where they address that same Flux Router host; batch speech-to-text posts multipart form data, which has no JSON body to put a field in at all. Flux Router honours the field on `/v1/chat/completions`, where it is what stops a retried turn being answered with a stored copy of an earlier reply. Its `/v1/responses` surface and both of its Anthropic Messages mounts — the bare `/v1/messages`, which is the path the default base URL reaches with `api_backend = "messages"`, and the prefixed `/anthropic/v1/messages` — rebuild each upstream request from a fixed field list, so the field never reaches the cache and they drop it. What protects a retry on those surfaces is the router's own cache instead: the `api.fluxrouter.ai` deployment released ahead of this version of Fuigo stops storing agent traffic at all. That is a property of that deployment rather than of the wire formats, so a self-hosted or older Flux Router may still replay a retry; Fuigo sends the field on every surface regardless, and the explicit opt-out takes effect the moment a surface honours it."#;

/// How much of each side to show either way of the first difference.
const DIFFERENCE_CONTEXT: usize = 40;

/// Where `actual` first differs from `expected` -- line, column, and that spot on both sides -- or the
/// empty string when they are identical.
///
/// [`the_user_guide_cache_paragraph_is_pinned_verbatim`] asserts two ~2 KB paragraphs are equal, and
/// `assert_eq!` prints both in full with no pointer to the delta. The pin exists to summon a human
/// reviewer, so it has to show that reviewer what moved rather than hand them two walls of prose.
fn first_difference(actual: &str, expected: &str) -> String {
    let actual: Vec<char> = actual.chars().collect();
    let expected: Vec<char> = expected.chars().collect();
    let Some(at) =
        (0..actual.len().max(expected.len())).find(|&at| actual.get(at) != expected.get(at))
    else {
        return String::new();
    };
    let (mut line, mut column) = (1usize, 1usize);
    for character in &actual[..at.min(actual.len())] {
        if *character == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    format!(
        "first difference at line {line}, column {column}\n  guide : {}\n  pinned: {}",
        difference_excerpt(&actual, at),
        difference_excerpt(&expected, at),
    )
}

/// `text` around `at`, with the character at `at` bracketed and the surroundings bounded, so a difference
/// deep inside a long line is still readable on one screen.
fn difference_excerpt(text: &[char], at: usize) -> String {
    let start = at.saturating_sub(DIFFERENCE_CONTEXT);
    let mut excerpt = String::new();
    if start > 0 {
        excerpt.push('\u{2026}');
    }
    excerpt.extend(&text[start..at.min(text.len())]);
    match text.get(at) {
        // A bare newline inside the brackets would break the report's own line; name it instead.
        Some('\n') => excerpt.push_str("[newline]"),
        Some(character) => {
            excerpt.push('[');
            excerpt.push(*character);
            excerpt.push(']');
        }
        None => excerpt.push_str("[end of text]"),
    }
    let tail = (at + 1).min(text.len());
    let end = (at + 1 + DIFFERENCE_CONTEXT).min(text.len());
    excerpt.extend(&text[tail..end]);
    if end < text.len() {
        excerpt.push('\u{2026}');
    }
    excerpt
}

/// The golden pin only works if the human it summons can see WHAT changed. `assert_eq!` on a 2 KB
/// paragraph prints the whole thing twice and leaves the reader to diff two walls of prose by eye, which
/// is how a one-word edit gets waved through. The report has to name the first differing line and column
/// and show that spot on both sides.
#[test]
fn the_golden_pin_failure_points_at_the_first_difference() {
    let report = first_difference("alpha bets gamma", "alpha beta gamma");
    assert!(
        report.contains("line 1, column 10"),
        "the report does not locate the first difference:\n{report}"
    );
    assert!(
        report.contains("bet[s] gamma") && report.contains("bet[a] gamma"),
        "the report does not show the differing character on both sides:\n{report}"
    );

    let multiline = first_difference("first line\nsecond LINE", "first line\nsecond line");
    assert!(
        multiline.contains("line 2, column 8"),
        "a difference on a later line is mislocated:\n{multiline}"
    );

    // One side running out is a difference too, and the side that ended has no character to bracket.
    let longer = first_difference("abcdef", "abc");
    assert!(
        longer.contains("line 1, column 4") && longer.contains("end of text"),
        "a text that only got longer is not reported as a difference:\n{longer}"
    );

    assert!(
        first_difference("same", "same").is_empty(),
        "identical texts must report no difference"
    );
}

/// Golden-text guard. See [`CACHE_PARAGRAPH`] for why this is an equality assertion and not a set of
/// vocabulary checks.
#[test]
fn the_user_guide_cache_paragraph_is_pinned_verbatim() {
    let paragraph = cache_paragraph();
    if paragraph == CACHE_PARAGRAPH {
        return;
    }
    panic!(
        "the Flux Router cache opt-out paragraph in \
         crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md no longer matches the \
         constant that pins it.\n\n{}\n\nTHIS PARAGRAPH'S CLAIMS MUST BE RE-VERIFIED AGAINST THE SOURCE \
         BEFORE THIS CONSTANT IS UPDATED. The rule it encodes: a request carries the body `cache` \
         field when it is built on the session's sampling client (`SamplingClient::body`, gated on \
         `fuigo_extra_ca::fluxrouter::is_fluxrouter_url` and off for a subscription transport) and \
         the resolved base URL is a Flux Router host -- that is every model turn on all three wire \
         formats plus every side call that rebuilds the session's sampling config through \
         `prepare_chat_completion`, which is an open-ended set and must never be written down as a \
         closed list. Web search carries it through its own `reqwest::Client` by applying the same \
         host rule itself. The media and audio paths (`/images/generations`, `/images/edits`, \
         `/videos/generations`, `/audio/transcriptions`) are built by different clients that never \
         add it. Seven rounds of review each found a different false claim in this paragraph, so \
         update the constant only after re-reading that code.\n\nThe guide now reads:\n{paragraph}",
        first_difference(&paragraph, CACHE_PARAGRAPH)
    );
}

/// Every paragraph in `11-custom-models.md` is one long line today, but hard-wrapping a Markdown file is
/// an ordinary edit that changes nothing a reader sees. The tests below read sentences, so the extraction
/// has to rebuild the paragraph from all of its lines: taking only the line the cache literal sits on
/// would cut the paragraph mid-sentence and fail these tests with "never names the surface", which is a
/// misleading report of a reflow.
#[test]
fn the_cache_paragraph_survives_a_hard_wrapped_guide() {
    let wrapped = format!(
        "## Default Models\n\nSome earlier paragraph about the default route.\n\nEvery model request \
         Fuigo sends to Flux Router carries the body field `{CACHE_FIELD}`.\nFlux Router honours it on \
         `/v1/chat/completions`, where it is what stops a retried\nturn being answered with a stored \
         copy. Its `/v1/responses` surface drops it.\n\nList all available models:\n"
    );
    // A wrap can land INSIDE the backticked literal too: Markdown gives a code span no protection from a
    // reflow, and the paragraph is then invisible to an extraction that looks for the literal before
    // rejoining the lines -- three tests panic at once on "the user guide describes the cache opt-out",
    // which is the least informative way a reflow can be reported.
    let split_literal = wrapped.replace(CACHE_FIELD, &CACHE_FIELD.replacen("true, ", "true,\n", 1));
    assert!(
        !split_literal.contains(CACHE_FIELD),
        "the fixture did not actually wrap the literal"
    );
    let across_the_literal = cache_paragraph_of(&split_literal);
    assert!(
        across_the_literal.contains("/v1/responses"),
        "a wrap inside the cache literal hid the paragraph from the extraction:\n{across_the_literal}"
    );

    let paragraph = cache_paragraph_of(&wrapped);
    assert!(
        paragraph.contains("/v1/responses"),
        "the extraction stopped at the line the cache field is on, so the rest of the paragraph is \
         invisible to every assertion below:\n{paragraph}"
    );
    let honours: Vec<&str> = sentences(&paragraph)
        .into_iter()
        .filter(|sentence| names_surface(sentence, "/v1/chat/completions"))
        .collect();
    assert!(
        honours
            .iter()
            .all(|sentence| sentence.contains("stored copy")),
        "a sentence broken across two source lines came out truncated, so a surface and its verdict no \
         longer share one sentence: {honours:?}"
    );
    // Only this paragraph, not the whole file: neighbouring paragraphs must not bleed in.
    assert!(
        !paragraph.contains("List all available models"),
        "the extraction ran past the blank line into the next paragraph:\n{paragraph}"
    );
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
    // Naming a deployment is not pinning one in time: "the api.fluxrouter.ai deployment stops storing
    // agent traffic" still reads as a standing fact. The claim has to relate that deployment to THIS
    // Fuigo, which is the release ordering the handoff records as a hard constraint.
    assert!(
        ["ahead of", "before", "as of", "since"]
            .iter()
            .any(|order| claim.contains(order)),
        "the router-cache claim names a deployment but never says WHEN it became true relative to this \
         Fuigo, so a reader of an older or newer binary cannot tell whether it applies:\n{claim}"
    );
    assert!(
        ["this version", "this release", "1.0.18"]
            .iter()
            .any(|anchor| claim.contains(anchor)),
        "the router-cache claim is not anchored to the version of Fuigo the reader is running, so the \
         ordering it states has nothing to order against:\n{claim}"
    );
    for scope in ["self-hosted", "older"] {
        assert!(
            paragraph.contains(scope),
            "the paragraph never says {scope:?}, so it does not tell the reader that another Flux Router \
             may still replay a retry:\n{paragraph}"
        );
    }
}
