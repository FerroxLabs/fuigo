use super::*;
use crate::session::quiesce::{self, ParkMode};
use crate::session::reverse_ticket;
use serde_json::json;

/// Records every frame the hold lets through, as `kind:session:tag`.
#[derive(Default)]
struct Recorder {
    seen: RefCell<Vec<String>>,
    /// The raw params of every `ext_method` the hold let through.
    params: RefCell<Vec<String>>,
}

struct Shared(Rc<Recorder>);

#[async_trait::async_trait(?Send)]
impl acp::Client for Shared {
    async fn request_permission(
        &self,
        args: acp::RequestPermissionRequest,
    ) -> acp::Result<acp::RequestPermissionResponse> {
        let released = released_flag(args.meta.as_ref());
        self.0
            .seen
            .borrow_mut()
            .push(format!("perm:{}{released}", args.session_id.0));
        Err(acp::Error::method_not_found())
    }

    async fn read_text_file(
        &self,
        args: acp::ReadTextFileRequest,
    ) -> acp::Result<acp::ReadTextFileResponse> {
        let released = released_flag(args.meta.as_ref());
        self.0
            .seen
            .borrow_mut()
            .push(format!("fs:{}{released}", args.session_id.0));
        Err(acp::Error::method_not_found())
    }

    async fn ext_method(&self, args: acp::ExtRequest) -> acp::Result<acp::ExtResponse> {
        let params = serde_json::from_str::<serde_json::Value>(args.params.get()).unwrap_or_default();
        let released = if params["_meta"][RELEASED_META_KEY] == serde_json::Value::Bool(true) {
            "+R"
        } else {
            ""
        };
        self.0.params.borrow_mut().push(args.params.get().to_owned());
        self.0.seen.borrow_mut().push(format!("extm:{}{released}", args.method));
        Ok(acp::ExtResponse::new(empty_raw()))
    }

    async fn session_notification(&self, args: acp::SessionNotification) -> acp::Result<()> {
        let tag = serde_json::to_value(&args.update)
            .ok()
            .and_then(|v| v["content"]["text"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let released = released_flag(args.meta.as_ref());
        self.0
            .seen
            .borrow_mut()
            .push(format!("su:{}:{tag}{released}", args.session_id.0));
        Ok(())
    }

    async fn ext_notification(&self, args: acp::ExtNotification) -> acp::Result<()> {
        let params = serde_json::from_str::<serde_json::Value>(args.params.get()).unwrap_or_default();
        let tag = params["tag"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| params["update"]["sessionUpdate"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let released = if params["_meta"][RELEASED_META_KEY] == serde_json::Value::Bool(true) {
            "+R"
        } else {
            ""
        };
        self.0
            .seen
            .borrow_mut()
            .push(format!("ext:{}:{tag}{released}", args.method));
        Ok(())
    }
}

fn released_flag(meta: Option<&acp::Meta>) -> &'static str {
    if meta.and_then(|m| m.get(RELEASED_META_KEY)) == Some(&serde_json::Value::Bool(true)) {
        "+R"
    } else {
        ""
    }
}

const MARKER: &str = "ext:fuigo/session_notification:unparked";

fn sid(tag: &str) -> String {
    format!("p189-hold-{tag}-{}", uuid::Uuid::new_v4())
}

fn chunk(session: &str, text: &str) -> acp::SessionNotification {
    serde_json::from_value(json!({
        "sessionId": session,
        "update": { "sessionUpdate": "agent_message_chunk", "content": { "type": "text", "text": text } }
    }))
    .expect("session notification")
}

fn ext(method: &str, params: serde_json::Value) -> acp::ExtNotification {
    let raw = serde_json::value::to_raw_value(&params).expect("raw params");
    acp::ExtNotification::new(method, raw.into())
}

fn permission(session: &str) -> acp::RequestPermissionRequest {
    serde_json::from_value(json!({
        "sessionId": session,
        "toolCall": { "toolCallId": "call-1" },
        "options": []
    }))
    .expect("permission request")
}

fn park(hold: &ParkFrameHold, session: &str) {
    let op = quiesce::begin_park(session, ParkMode::Hold).expect("not parked yet");
    assert!(quiesce::complete_park(session, op));
    hold.mark_parked(session);
}

fn client(hold: &Rc<ParkFrameHold>) -> (ParkHoldClient<Shared>, Rc<Recorder>) {
    let recorder = Rc::new(Recorder::default());
    (
        ParkHoldClient::new(Shared(recorder.clone()), hold.clone()),
        recorder,
    )
}

/// A parked session's frames (session updates, its `_fuigo/*` notifications and process-wide frames) are
/// held; another session's frames pass. Unpark writes the held ones in their original order.
#[tokio::test(flavor = "current_thread")]
async fn parked_frames_are_held_then_released_in_order() {
    use acp::Client as _;
    let hold = ParkFrameHold::new();
    let (conn, seen) = client(&hold);
    let parked = sid("parked");
    let other = sid("other");
    park(&hold, &parked);

    conn.session_notification(chunk(&parked, "a")).await.unwrap();
    conn.ext_notification(ext(
        "fuigo/session_notification",
        json!({ "sessionId": parked, "tag": "summary" }),
    ))
    .await
    .unwrap();
    conn.ext_notification(ext("fuigo/announcements", json!({ "tag": "global" })))
        .await
        .unwrap();
    conn.session_notification(chunk(&other, "o")).await.unwrap();
    assert_eq!(*seen.seen.borrow(), vec![format!("su:{other}:o")]);
    assert_eq!(hold.held_frames(), 3);

    quiesce::unpark(&parked);
    let counts = hold.release(&parked).await;
    assert_eq!(counts, ReleaseCounts { frames: 3, dropped: 0 });
    assert_eq!(
        *seen.seen.borrow(),
        vec![
            format!("su:{other}:o"),
            format!("su:{parked}:a+R"),
            "ext:fuigo/session_notification:summary+R".to_owned(),
            "ext:fuigo/announcements:global+R".to_owned(),
            MARKER.to_owned(),
        ],
        "released frames are marked, in order, then the unparked marker"
    );
    conn.session_notification(chunk(&parked, "b")).await.unwrap();
    assert_eq!(seen.seen.borrow().last().unwrap(), &format!("su:{parked}:b"));
}

/// A frame produced after the park ended but before this connection released (another path ended it:
/// the session closed, or another connection unparked) first writes the session's older held frames, so the
/// client never sees them out of order and nothing stays stuck.
#[tokio::test(flavor = "current_thread")]
async fn a_frame_racing_the_release_keeps_its_place() {
    use acp::Client as _;
    let hold = ParkFrameHold::new();
    let (conn, seen) = client(&hold);
    let parked = sid("parked");
    park(&hold, &parked);
    conn.session_notification(chunk(&parked, "old")).await.unwrap();
    quiesce::unpark(&parked);
    conn.session_notification(chunk(&parked, "new")).await.unwrap();
    assert_eq!(
        *seen.seen.borrow(),
        vec![format!("su:{parked}:old+R"), format!("su:{parked}:new")]
    );
    assert_eq!(hold.release(&parked).await.frames, 0);
    assert_eq!(seen.seen.borrow().last().unwrap(), MARKER);
}

/// A subagent of a parked root is quiesced with it: its frames are held too.
#[tokio::test(flavor = "current_thread")]
async fn a_parked_roots_subagent_frames_are_held() {
    use acp::Client as _;
    let hold = ParkFrameHold::new();
    let (conn, seen) = client(&hold);
    let root = sid("root");
    let child = sid("child");
    let _link = quiesce::SessionGuard::new(&child, Some(&root));
    park(&hold, &root);
    conn.session_notification(chunk(&child, "c")).await.unwrap();
    assert!(seen.seen.borrow().is_empty());
    quiesce::unpark(&root);
    hold.release(&root).await;
    assert_eq!(
        *seen.seen.borrow(),
        vec![format!("su:{child}:c+R"), MARKER.to_owned()]
    );
}

/// A parked session's request (a background subagent's permission prompt) is not sent until unpark.
#[tokio::test(flavor = "current_thread")]
async fn a_parked_sessions_request_waits_for_unpark() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let parked = sid("parked");
            park(&hold, &parked);
            let conn = Rc::new(conn);
            let request = {
                let conn = conn.clone();
                let parked = parked.clone();
                tokio::task::spawn_local(async move {
                    let _ = conn.request_permission(permission(&parked)).await;
                })
            };
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert!(seen.seen.borrow().is_empty(), "the request was sent while parked");
            quiesce::unpark(&parked);
            hold.release(&parked).await;
            tokio::time::timeout(std::time::Duration::from_secs(5), request)
                .await
                .expect("unpark releases the request")
                .expect("request task");
            assert_eq!(
                *seen.seen.borrow(),
                vec![MARKER.to_owned(), format!("perm:{parked}+R")],
                "an explicit unpark sends the held request, marked released"
            );
        })
        .await;
}

/// An implicit unpark (a new prompt) answers the old turn's held permission request `cancelled` and never
/// sends it.
#[tokio::test(flavor = "current_thread")]
async fn implicit_unpark_cancels_held_requests() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let parked = sid("parked");
            park(&hold, &parked);
            let conn = Rc::new(conn);
            let request = {
                let conn = conn.clone();
                let parked = parked.clone();
                tokio::task::spawn_local(async move { conn.request_permission(permission(&parked)).await })
            };
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            quiesce::note_implicit_unpark(&parked);
            quiesce::unpark(&parked);
            hold.release(&parked).await;
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), request)
                .await
                .expect("implicit unpark answers the request")
                .expect("request task")
                .expect("a cancelled outcome, not an error");
            assert!(matches!(outcome.outcome, acp::RequestPermissionOutcome::Cancelled));
            assert_eq!(*seen.seen.borrow(), vec![MARKER.to_owned()], "the request was sent");
        })
        .await;
}

/// Nothing parked: every frame goes straight through.
#[tokio::test(flavor = "current_thread")]
async fn nothing_is_held_without_a_park() {
    use acp::Client as _;
    let hold = ParkFrameHold::new();
    let (conn, seen) = client(&hold);
    let session = sid("live");
    conn.session_notification(chunk(&session, "x")).await.unwrap();
    conn.ext_notification(ext("fuigo/announcements", json!({ "tag": "g" })))
        .await
        .unwrap();
    assert_eq!(seen.seen.borrow().len(), 2);
    assert_eq!(hold.held_frames(), 0);
}

/// Astra r1 #11: a held fs/terminal request sent by an explicit unpark carries `_meta["fuigo/released"]`, like
/// a held permission request.
#[tokio::test(flavor = "current_thread")]
async fn released_fs_and_terminal_requests_are_marked() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let parked = sid("parked");
            park(&hold, &parked);
            let conn = Rc::new(conn);
            let request = {
                let conn = conn.clone();
                let parked = parked.clone();
                tokio::task::spawn_local(async move {
                    let req: acp::ReadTextFileRequest =
                        serde_json::from_value(json!({ "sessionId": parked, "path": "/tmp/x" }))
                            .expect("read request");
                    let _ = conn.read_text_file(req).await;
                })
            };
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert!(seen.seen.borrow().is_empty(), "the request was sent while parked");
            quiesce::unpark(&parked);
            hold.release(&parked).await;
            tokio::time::timeout(std::time::Duration::from_secs(5), request)
                .await
                .expect("unpark releases the request")
                .expect("request task");
            assert_eq!(
                *seen.seen.borrow(),
                vec![MARKER.to_owned(), format!("fs:{parked}+R")],
                "a released fs request must be marked released"
            );
        })
        .await;
}

/// Astra r1 #9: closing a parked root (its actor guard drops) must stop this connection holding
/// process-wide frames; a later frame goes straight out.
#[tokio::test(flavor = "current_thread")]
async fn closing_a_parked_root_stops_holding_process_wide_frames() {
    use acp::Client as _;
    let hold = ParkFrameHold::new();
    let (conn, seen) = client(&hold);
    let root = sid("root");
    {
        let _guard = quiesce::SessionGuard::new(&root, None);
        park(&hold, &root);
    }
    conn.ext_notification(ext("fuigo/announcements", json!({ "tag": "after-close" })))
        .await
        .unwrap();
    assert_eq!(
        *seen.seen.borrow(),
        vec!["ext:fuigo/announcements:after-close".to_owned()],
        "a closed root still holds process-wide frames"
    );
}

fn sdk_call() -> acp::ExtRequest {
    let params = serde_json::value::to_raw_value(&json!({ "serverId": "srv_0", "message": {} })).unwrap();
    acp::ExtRequest::new("fuigo/mcp/sdk_call", std::sync::Arc::from(params))
}

/// Astra r2 #6: a reverse `fuigo/mcp/sdk_call` goes through the hold: while a live park holds the connection (and
/// no parked load is being answered) it waits, and it goes out after the unpark marked `fuigo/released`.
#[tokio::test(flavor = "current_thread")]
async fn reverse_mcp_calls_are_held_by_a_live_park_and_marked_released() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let parked = sid("parked-sdk");
            park(&hold, &parked);
            let conn = Rc::new(conn);
            let call = {
                let conn = conn.clone();
                tokio::task::spawn_local(async move { conn.ext_method(sdk_call()).await })
            };
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert!(seen.seen.borrow().is_empty(), "a reverse MCP call went out while parked: {:?}", seen.seen.borrow());
            quiesce::unpark(&parked);
            hold.release(&parked).await;
            tokio::time::timeout(std::time::Duration::from_secs(5), call)
                .await
                .expect("the unpark releases the call")
                .expect("task")
                .expect("answered");
            assert!(
                seen.seen.borrow().contains(&"extm:fuigo/mcp/sdk_call+R".to_owned()),
                "the released call was not marked: {:?}",
                seen.seen.borrow()
            );
        })
        .await;
}

/// A reverse MCP call CREATED during a parked load's own window (its ticket says so) goes straight out, unmarked.
#[tokio::test(flavor = "current_thread")]
async fn reverse_mcp_calls_of_a_parked_load_window_go_out() {
    use acp::Client as _;
    let hold = ParkFrameHold::new();
    let (conn, seen) = client(&hold);
    let parked = sid("parked-load");
    park(&hold, &parked);
    let _load = quiesce::begin_parked_load(&parked);
    let ticket = reverse_ticket::create(&parked);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.ext_method(sdk_call_with(ticket.id())),
    )
    .await
    .expect("a parked load's call is not held")
    .expect("answered");
    assert_eq!(*seen.seen.borrow(), vec!["extm:fuigo/mcp/sdk_call".to_owned()]);
    quiesce::unpark(&parked);
}

fn sdk_call_with(ticket: u64) -> acp::ExtRequest {
    let params = serde_json::value::to_raw_value(&json!({
        "serverId": "srv_0",
        "message": {},
        "_meta": { reverse_ticket::TICKET_META_KEY: ticket },
    }))
    .unwrap();
    acp::ExtRequest::new("fuigo/mcp/sdk_call", std::sync::Arc::from(params))
}

async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

/// F5: a call created while its session was not parked, queued before the park, is held by ITS session's park
/// even while another session's parked load is being answered (it is not "any parked load").
#[tokio::test(flavor = "current_thread")]
async fn a_call_queued_before_its_park_is_not_let_out_by_another_sessions_load_window() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let (a, b) = (sid("queued-a"), sid("load-b"));
            let ticket = reverse_ticket::create(&a);
            park(&hold, &a);
            park(&hold, &b);
            let _load = quiesce::begin_parked_load(&b);
            let conn = Rc::new(conn);
            let id = ticket.id();
            let call = {
                let conn = conn.clone();
                tokio::task::spawn_local(async move { conn.ext_method(sdk_call_with(id)).await })
            };
            settle().await;
            assert!(seen.seen.borrow().is_empty(), "went out under B's load window: {:?}", seen.seen.borrow());
            quiesce::unpark(&b);
            quiesce::unpark(&a);
            hold.release(&a).await;
            tokio::time::timeout(std::time::Duration::from_secs(5), call)
                .await
                .expect("A's unpark releases the call")
                .expect("task")
                .expect("answered");
            assert!(seen.seen.borrow().contains(&"extm:fuigo/mcp/sdk_call+R".to_owned()), "{:?}", seen.seen.borrow());
        })
        .await;
}

/// F5: a call of A that waited out A's park is released; B parking on the same connection afterwards does not
/// hold it again.
#[tokio::test(flavor = "current_thread")]
async fn a_released_call_of_a_is_not_held_by_bs_park_on_the_same_connection() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let (a, b) = (sid("released-a"), sid("park-b"));
            park(&hold, &a);
            let ticket = reverse_ticket::create(&a);
            let id = ticket.id();
            let invoker = tokio::task::spawn_local(async move {
                let t = reverse_ticket::lookup(id).expect("live ticket");
                t.wait_admitted().await
            });
            settle().await;
            quiesce::unpark(&a);
            hold.release(&a).await;
            assert_eq!(invoker.await.expect("task"), Ok(true), "the invoker waited out A's park");
            park(&hold, &b);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                conn.ext_method(sdk_call_with(id)),
            )
            .await;
            quiesce::unpark(&b);
            result.expect("B's park held A's released call").expect("answered");
            assert!(seen.seen.borrow().contains(&"extm:fuigo/mcp/sdk_call+R".to_owned()), "{:?}", seen.seen.borrow());
        })
        .await;
}

/// F5/F10: when the invoker gives up (its guard drops), the held gateway request ends cancelled and is never sent.
#[tokio::test(flavor = "current_thread")]
async fn an_invoker_timeout_removes_the_held_gateway_request() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let a = sid("timeout-a");
            let ticket = reverse_ticket::create(&a);
            let id = ticket.id();
            park(&hold, &a);
            let conn = Rc::new(conn);
            let call = {
                let conn = conn.clone();
                tokio::task::spawn_local(async move { conn.ext_method(sdk_call_with(id)).await })
            };
            settle().await;
            assert!(!call.is_finished(), "the call was not held");
            drop(ticket);
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), call)
                .await
                .expect("dropping the guard ends the held request")
                .expect("task");
            assert!(result.is_err(), "a cancelled call answered");
            assert!(reverse_ticket::lookup(id).is_none());
            assert!(seen.seen.borrow().is_empty(), "{:?}", seen.seen.borrow());
            quiesce::unpark(&a);
        })
        .await;
}

/// The internal ticket key never reaches the inner client (the wire): released or not, `sdk_call` or not, and
/// an emptied `_meta` is removed with it.
#[tokio::test(flavor = "current_thread")]
async fn the_internal_ticket_is_never_written() {
    use acp::Client as _;
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let hold = ParkFrameHold::new();
            let (conn, seen) = client(&hold);
            let a = sid("strip-a");
            let ticket = reverse_ticket::create(&a);
            conn.ext_method(sdk_call_with(ticket.id())).await.expect("unreleased call");
            // A released call (it waited out a park).
            park(&hold, &a);
            let released = reverse_ticket::create(&a);
            let id = released.id();
            let conn = Rc::new(conn);
            let call = {
                let conn = conn.clone();
                tokio::task::spawn_local(async move { conn.ext_method(sdk_call_with(id)).await })
            };
            settle().await;
            quiesce::unpark(&a);
            hold.release(&a).await;
            call.await.expect("task").expect("released call");
            // Another method carrying the key is stripped too.
            let raw = serde_json::value::to_raw_value(&json!({
                "x": 1, "_meta": { reverse_ticket::TICKET_META_KEY: 7, "keep": true }
            }))
            .unwrap();
            conn.ext_method(acp::ExtRequest::new("fuigo/other", std::sync::Arc::from(raw)))
                .await
                .expect("other method");
            let written = seen.params.borrow().clone();
            assert_eq!(written.len(), 3, "{written:?}");
            for params in &written {
                assert!(!params.contains(reverse_ticket::TICKET_META_KEY), "the ticket was written: {params}");
            }
            let first: serde_json::Value = serde_json::from_str(&written[0]).unwrap();
            assert!(first.get("_meta").is_none(), "an emptied _meta stays: {first}");
            assert_eq!(first["serverId"], "srv_0");
            let second: serde_json::Value = serde_json::from_str(&written[1]).unwrap();
            assert_eq!(second["_meta"][RELEASED_META_KEY], serde_json::Value::Bool(true));
            let third: serde_json::Value = serde_json::from_str(&written[2]).unwrap();
            assert_eq!(third["_meta"]["keep"], serde_json::Value::Bool(true));
        })
        .await;
}

/// Grok r4 #6: a call created while its tree was parked (outside any load window) that finds the park already
/// ended at its first admission check still goes out marked `fuigo/released`, not unmarked.
#[tokio::test(flavor = "current_thread")]
async fn a_ticket_created_while_parked_is_marked_released_when_an_unpark_won_first() {
    let parked = sid("p189a2-ticket-unpark-first");
    let op = quiesce::begin_park(&parked, ParkMode::Hold).expect("park");
    assert!(quiesce::complete_park(&parked, op));
    let ticket = reverse_ticket::create(&parked);
    quiesce::unpark(&parked); // explicit unpark: the generation is not bumped
    let released = tokio::time::timeout(std::time::Duration::from_secs(5), ticket.ticket().wait_admitted())
        .await
        .expect("admitted")
        .expect("not cancelled");
    assert!(released, "the call went out unmarked after the park it was created under");
}

/// A call created while nothing is parked is never marked.
#[tokio::test(flavor = "current_thread")]
async fn a_ticket_created_without_a_park_is_not_marked_released() {
    let id = sid("p189a2-ticket-no-park");
    let ticket = reverse_ticket::create(&id);
    let released = ticket.ticket().wait_admitted().await.expect("admitted");
    assert!(!released);
}
