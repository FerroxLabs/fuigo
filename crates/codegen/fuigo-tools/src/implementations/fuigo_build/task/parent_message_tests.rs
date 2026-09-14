use super::*;

/// Level-triggered: a message committed before the watch was taken still
/// resolves it. The parent's message is usually committed while the model is
/// sampling, i.e. before the next wait subscribes.
#[tokio::test]
async fn watch_reports_a_message_committed_before_it_subscribed() {
    let signal = ParentMessageSignal::new();
    signal.message_committed("parent-message-early");
    let watch = signal.subscribe();
    let ids = tokio::time::timeout(std::time::Duration::from_millis(500), watch.arrived())
        .await
        .expect("an already-pending message must resolve the watch at once");
    assert_eq!(&*ids, ["parent-message-early".to_string()]);
}

/// ...and stops resolving once the message has reached the model, so one
/// interrupt cannot become a tool-call loop.
#[tokio::test]
async fn watch_ignores_a_message_that_has_already_been_delivered() {
    let signal = ParentMessageSignal::new();
    signal.message_committed("parent-message-early");
    signal.message_delivered("parent-message-early");
    let watch = signal.subscribe();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), watch.arrived())
            .await
            .is_err(),
        "a delivered message must not interrupt the next wait"
    );
}

/// `message_delivered` is per-identifier: a second, still-undelivered message
/// must survive the first one's delivery.
#[tokio::test]
async fn delivering_one_message_leaves_the_others_pending() {
    let signal = ParentMessageSignal::new();
    signal.message_committed("m1");
    signal.message_committed("m2");
    signal.message_delivered("m1");
    assert_eq!(signal.pending_message_ids(), vec!["m2".to_string()]);
}

#[tokio::test]
async fn watch_resolves_with_pending_ids_on_a_later_commit() {
    let signal = ParentMessageSignal::new();
    let watch = signal.subscribe();
    let waiter = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), watch.arrived())
            .await
            .expect("watch must resolve once a message is committed")
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    signal.message_committed("parent-message-late");
    let ids = waiter.await.expect("waiter task");
    assert_eq!(&*ids, ["parent-message-late".to_string()]);
    assert_eq!(signal.pending_message_ids(), vec!["parent-message-late"]);
    signal.message_delivered("parent-message-late");
    assert!(signal.pending_message_ids().is_empty());
}

#[tokio::test]
async fn watch_reports_every_pending_message() {
    let signal = ParentMessageSignal::new();
    let watch = signal.subscribe();
    signal.message_committed("a");
    signal.message_committed("b");
    let ids = tokio::time::timeout(std::time::Duration::from_secs(5), watch.arrived())
        .await
        .expect("watch must resolve");
    assert_eq!(&*ids, ["a".to_string(), "b".to_string()]);
}
