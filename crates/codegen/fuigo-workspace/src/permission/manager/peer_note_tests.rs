//! S6.7 (packet 6 part B2): the classifier request carries the turn origin and the influenced flag only for an influenced
//! session or a peer-origin turn; otherwise its bytes are unchanged.

use super::*;
use crate::permission::auto_mode::{ClassifierFailure, ClassifierMessage, LlmPermissionClassifier};
use std::sync::Mutex as StdMutex;

fn spawn(cwd: &AbsPathBuf) -> PermissionHandle {
    let (tx, _rx) = mpsc::unbounded_channel();
    let (h, _events) = spawn_permission_manager_with_pin(
        acp::SessionId::new(Arc::from("peer-note")),
        GatewaySender::new(tx),
        cwd.clone(),
        ClientType::Generic,
        None,
        vec![],
        vec![],
        false,
        None,
        true,
        None,
        None,
    );
    h
}

type Captured = Arc<StdMutex<Vec<Vec<ClassifierMessage>>>>;

fn capture(h: &PermissionHandle) -> Captured {
    let seen: Captured = Arc::default();
    let sink = seen.clone();
    h.set_auto_mode(true);
    h.set_classifier(Some(Arc::new(LlmPermissionClassifier {
        classify_text: Some(Arc::new(move |messages: Vec<ClassifierMessage>| {
            sink.lock().unwrap().push(messages);
            Box::pin(async { Ok::<_, ClassifierFailure>(r#"{"shouldBlock":false,"reason":"ok","thinking":"t"}"#.to_owned()) })
        })),
        ..LlmPermissionClassifier::default()
    })));
    seen
}

async fn classify_once(h: &PermissionHandle) {
    let req = PermissionRequest::new(
        AccessKind::MCPTool { name: "test_server__do_thing".into(), input: serde_json::Value::Null },
        acp::ToolCallUpdate::new("t1", acp::ToolCallUpdateFields::new()),
    );
    let _ = h.request(req).await;
}

fn text_of(seen: &Captured) -> String {
    seen.lock().unwrap().iter().flatten().map(|m| m.text.clone()).collect::<Vec<_>>().join("\n")
}

#[tokio::test]
async fn classifier_request_carries_origin_and_flag_when_influenced() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = AbsPathBuf::new(tmp.path().to_path_buf()).unwrap();
            let h = spawn(&cwd);
            let seen = capture(&h);
            h.set_peer_influenced(true);
            h.peer_influence().set_peer_turn(true);
            classify_once(&h).await;
            let t = text_of(&seen);
            assert!(t.contains("peer_influenced: true") && t.contains("turn origin: peer_message"), "{t}");
        })
        .await;
}

#[tokio::test]
async fn classifier_request_is_unchanged_when_not_influenced() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let tmp = tempfile::tempdir().unwrap();
            let cwd = AbsPathBuf::new(tmp.path().to_path_buf()).unwrap();
            let h = spawn(&cwd);
            let seen = capture(&h);
            classify_once(&h).await;
            assert!(!seen.lock().unwrap().is_empty(), "the classifier ran");
            let t = text_of(&seen);
            assert!(!t.contains("peer_influenced") && !t.contains("turn origin"), "{t}");
            // After a clear the request is the same again.
            h.set_peer_influenced(true);
            h.set_peer_influenced(false);
            classify_once(&h).await;
            let msgs = seen.lock().unwrap().clone();
            assert_eq!(msgs[0].len(), msgs[1].len());
            assert!(msgs[0].iter().zip(&msgs[1]).all(|(a, b)| a.text == b.text));
        })
        .await;
}

#[test]
fn payload_note_follows_the_flag_and_the_turn_origin() {
    let f = crate::permission::PeerInfluence::new();
    assert_eq!(f.payload_note(), None);
    f.set(true);
    let n = f.payload_note().unwrap();
    assert!(n.peer_influenced && n.origin.is_none());
    f.set_peer_turn(true);
    assert_eq!(f.payload_note().unwrap().origin.as_deref(), Some("peer_message"));
    // The turn flag is shared by clones, like the influenced flag.
    let g = f.clone();
    g.set(false);
    g.set_peer_turn(false);
    assert_eq!(f.payload_note(), None);
}

#[test]
fn build_classifier_messages_without_a_note_has_no_peer_text() {
    use crate::permission::auto_mode::{ClassifierContext, ClassifierPromptType, build_classifier_messages};
    let access = AccessKind::Bash("make x".into());
    let plain = build_classifier_messages("run_terminal_command", &access, Some("make x"), &ClassifierContext::default(), ClassifierPromptType::Full);
    let with = ClassifierContext {
        peer: Some(crate::permission::PeerPayloadNote { origin: None, peer_influenced: true }),
        ..ClassifierContext::default()
    };
    let noted = build_classifier_messages("run_terminal_command", &access, Some("make x"), &with, ClassifierPromptType::Full);
    assert_eq!(noted.len(), plain.len() + 1);
    assert!(plain.iter().all(|m| !m.text.contains("peer_influenced")));
    assert!(noted.iter().any(|m| m.text.contains("peer_influenced: true") && m.text.contains("turn origin: not peer_message")));
}
