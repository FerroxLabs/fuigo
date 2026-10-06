//! Every write to the process-wide trust set reaches the injected record sink,
//! whoever the caller is, whether it happens before or after the sink exists,
//! losslessly and in the order the writes took effect.
//!
//! One test function on purpose: the trust set and the sink are process-wide, so
//! the order of the steps below is the thing under test.

use fuigo_shell_base::util::{
    TrustRecordSink, TrustSetChange, TrustWritePath, TrustedApiOrigins, TrustedOriginAuthority,
    claim_trusted_origin_authority, flush_trust_records, install_trust_record_sink,
    set_trusted_api_origins,
};
use std::sync::{Arc, Mutex, OnceLock};

static AUTHORITY: OnceLock<TrustedOriginAuthority> = OnceLock::new();

#[derive(Default)]
struct Collect {
    seen: Mutex<Vec<(TrustSetChange, TrustWritePath)>>,
    reentered: Mutex<bool>,
    panic_next: Mutex<bool>,
}

/// Local wrapper: the trait and `Arc` are both foreign to this test crate.
struct Sink(Arc<Collect>);

impl TrustRecordSink for Sink {
    fn record(&self, change: &TrustSetChange, via: TrustWritePath) {
        if std::mem::take(&mut *self.0.panic_next.lock().unwrap()) {
            panic!("sink panics once");
        }
        self.0.seen.lock().unwrap().push((change.clone(), via));
        // A sink that writes the trust set again must not deadlock, and its write
        // must still be recorded, after the one being delivered.
        let mut reentered = self.0.reentered.lock().unwrap();
        if !*reentered && matches!(change, TrustSetChange::Changed { .. }) {
            *reentered = true;
            drop(reentered);
            publish("reentrant");
        }
    }
}

fn publish(name: &str) {
    AUTHORITY
        .get()
        .unwrap()
        .publish(TrustedApiOrigins::new([format!(
            "https://{name}.example/v1"
        )]));
}

/// Each `Changed` must start from where the record before it ended: a reordered or
/// dropped record breaks the chain.
fn assert_chain(seen: &[(TrustSetChange, TrustWritePath)]) {
    let mut last = None;
    for (i, (change, _)) in seen.iter().enumerate() {
        match change {
            TrustSetChange::Initial { current } => {
                assert_eq!(i, 0, "baseline must come first");
                last = Some(current.clone());
            }
            TrustSetChange::Changed {
                previous, current, ..
            } => {
                assert_eq!(
                    Some(previous),
                    last.as_ref(),
                    "record {i} out of order or a record is missing"
                );
                last = Some(current.clone());
            }
            TrustSetChange::Unchanged { .. } => panic!("unchanged republish was recorded"),
        }
    }
}

#[test]
fn every_trust_write_reaches_the_sink_in_order_without_loss() {
    // Before any sink exists: a seed write by a caller that never heard of it.
    assert!(set_trusted_api_origins(["https://seed.example/v1".to_string()]).is_some());
    AUTHORITY
        .set(claim_trusted_origin_authority().expect("first claim"))
        .ok()
        .unwrap();
    // Far more than any fixed buffer would hold.
    for i in 0..100 {
        publish(&format!("pre{i}"));
    }

    let sink = Arc::new(Collect::default());
    assert!(install_trust_record_sink(Arc::new(Sink(sink.clone()))));
    // 1 seed + 100 publishes + 1 write made from inside the sink.
    {
        let seen = sink.seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            102,
            "writes made before install are all replayed"
        );
        assert_eq!(seen[0].1, TrustWritePath::Seed);
        assert_eq!(seen[1].1, TrustWritePath::Authority);
        assert_chain(&seen);
    }

    // After install: concurrent publishers; unchanged republishes are not recorded.
    publish("reentrant");
    std::thread::scope(|scope| {
        for t in 0..4 {
            scope.spawn(move || {
                for i in 0..50 {
                    publish(&format!("t{t}-{i}"));
                }
            });
        }
    });
    let seen = sink.seen.lock().unwrap();
    assert_eq!(
        seen.len(),
        102 + 200,
        "no record lost under concurrent writers"
    );
    assert_chain(&seen);
    drop(seen);

    // A sink that panics: the panic reaches the writer, the trust write still took
    // effect, and nothing is lost -- the record is delivered by the next flush.
    *sink.panic_next.lock().unwrap() = true;
    let result = std::panic::catch_unwind(|| publish("panicker"));
    assert!(result.is_err(), "the sink's panic is not swallowed");
    assert_eq!(
        sink.seen.lock().unwrap().len(),
        302,
        "panicked record not yet delivered"
    );
    flush_trust_records();
    assert_eq!(sink.seen.lock().unwrap().len(), 303);
    assert_chain(&sink.seen.lock().unwrap());

    // A second install is refused and does not displace the first. The rejected
    // sink's destructor writes the trust set: it must run outside every lock.
    struct PublishOnDrop;
    impl TrustRecordSink for PublishOnDrop {
        fn record(&self, _: &TrustSetChange, _: TrustWritePath) {}
    }
    impl Drop for PublishOnDrop {
        fn drop(&mut self) {
            publish("from-destructor");
        }
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let refused = !install_trust_record_sink(Arc::new(PublishOnDrop));
        tx.send(refused).ok();
    });
    let refused = rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("installing a refused sink deadlocked");
    assert!(refused);
    assert_eq!(
        sink.seen.lock().unwrap().len(),
        304,
        "destructor's write recorded"
    );
    publish("after-refusal");
    assert_eq!(sink.seen.lock().unwrap().len(), 305);
    assert_chain(&sink.seen.lock().unwrap());
}
