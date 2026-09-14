use super::*;

#[tokio::test]
async fn watch_ignores_messages_committed_before_it_subscribed() {
    let signal = ParentMessageSignal::new();
    signal.message_committed("parent-message-early");
    let watch = signal.subscribe();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), watch.arrived())
            .await
            .is_err(),
        "a message committed before the wait began must not interrupt it"
    );
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
    assert_eq!(signal.take_pending(), vec!["parent-message-late"]);
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
