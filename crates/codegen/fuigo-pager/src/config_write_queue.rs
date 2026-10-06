//! The pager's `config.toml` writes, off the input thread and in order (P49).
//!
//! Every write the pager makes on a user action (dismissing a plugin prompt,
//! the agents modal's `s`/`t`, `/provider`) waits for `config.toml.lock`, so
//! it must not run on the input thread. Running each on the blocking pool
//! would lose their ORDER: two `/provider` commands for the same model could
//! commit in reverse, the older one winning. So they all go to one worker
//! thread, which runs them one at a time in the order they were submitted.
//! Submission happens on the event-loop thread as effects are handled, which
//! is the order the user made them.

use std::sync::mpsc;
use std::sync::{Mutex, PoisonError};

/// A queued write. Called with `None` to run it, or with `Some(reason)` when
/// it cannot run: it then records `reason` as its (pending) failure.
type Job = Box<dyn FnOnce(Option<String>) + Send + 'static>;

/// The worker's queue. Started on first use; if it cannot be started (or has
/// gone), the next submission tries again. A write is never run outside the
/// worker: that would give up the ordering.
static QUEUE: WriteQueue = WriteQueue {
    sender: Mutex::new(None),
    start: start_worker,
};

/// The queue's state: the running worker's sender, and how to start one
/// (a parameter only so tests can make starting fail).
struct WriteQueue {
    sender: Mutex<Option<mpsc::Sender<Job>>>,
    start: fn() -> std::io::Result<mpsc::Sender<Job>>,
}

fn start_worker() -> std::io::Result<mpsc::Sender<Job>> {
    let (tx, rx) = mpsc::channel::<Job>();
    std::thread::Builder::new()
        .name("fuigo-config-writes".to_owned())
        .spawn(move || {
            for job in rx {
                job(None);
            }
        })?;
    Ok(tx)
}

/// Failures not yet shown to the user, by id. A failure stays here from the
/// moment the write fails until whoever shows it calls
/// [`WriteFailure::acknowledge`]; one still here at exit (its receiver, task or
/// task result dropped by the quit) is reported by [`drain`].
static PENDING_FAILURES: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());

/// A failed config write. Its message stays pending until acknowledged.
#[derive(Debug)]
pub struct WriteFailure {
    /// 0 for a failure that was never pending (the write never ran).
    id: u64,
    message: String,
}

impl WriteFailure {
    /// A failure reported directly to the requester (not held for exit).
    pub(crate) fn unqueued(message: impl Into<String>) -> Self {
        Self {
            id: 0,
            message: message.into(),
        }
    }

    /// The message, for showing; marks it shown, so `drain` will not repeat it.
    /// Call it where the failure is actually presented.
    pub(crate) fn acknowledge(self) -> String {
        if self.id != 0 {
            PENDING_FAILURES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|(id, _)| *id != self.id);
        }
        self.message
    }
}

/// Run `write` on the config write worker, after every write submitted before
/// it; the receiver yields its result. Never blocks on the write itself.
///
/// A failure is held pending (see [`WriteFailure`]) until it is acknowledged,
/// so one that never reaches the user before a quit is reported by [`drain`].
///
/// If the worker cannot be started, `write` is not run (never out of order)
/// and its result is a pending failure saying so.
pub(crate) fn run<T: Send + 'static>(
    write: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> tokio::sync::oneshot::Receiver<Result<T, WriteFailure>> {
    QUEUE.run(write)
}

impl WriteQueue {
    fn run<T: Send + 'static>(
        &self,
        write: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> tokio::sync::oneshot::Receiver<Result<T, WriteFailure>> {
        static NEXT_FAILURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let job: Job = Box::new(move |cannot_run: Option<String>| {
            let result = match cannot_run {
                None => {
                    // A panicking write must not stop the ones queued after it,
                    // and is a failure like any other.
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(write)).unwrap_or_else(|_| {
                        tracing::warn!("a config write panicked");
                        Err("the write panicked".to_owned())
                    })
                }
                Some(reason) => Err(reason),
            };
            let result = result.map_err(|message| {
                let id = NEXT_FAILURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                PENDING_FAILURES
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id, message.clone()));
                WriteFailure { id, message }
            });
            let _ = tx.send(result);
        });
        // The lock is held only to enqueue (or start the worker), which keeps
        // submissions in the order the callers made them.
        let mut queue = self.sender.lock().unwrap_or_else(PoisonError::into_inner);
        let job = match queue.as_ref() {
            Some(q) => match q.send(job) {
                Ok(()) => return rx,
                // The worker is gone: start another below.
                Err(mpsc::SendError(job)) => job,
            },
            None => job,
        };
        match (self.start)() {
            Ok(q) => {
                // A new worker has an empty queue and nothing queued before this
                // job is still pending, so order holds.
                let _ = q.send(job);
                *queue = Some(q);
            }
            Err(e) => {
                *queue = None;
                not_started(job, &e);
            }
        }
        rx
    }
}

/// A write the worker could not be started for: not run (never out of
/// order), and recorded as a pending failure like any other, so it is shown by
/// the requester or, failing that, at exit.
fn not_started(job: Job, error: &dyn std::fmt::Display) {
    tracing::warn!(%error, "could not start the config write worker; write not run");
    job(Some(format!("could not start the config write worker: {error}")));
}

/// What [`drain`] found at exit.
#[derive(Debug, Default)]
pub(crate) struct DrainReport {
    /// Failed writes never shown to the user.
    pub(crate) failures: Vec<String>,
    /// Writes were still pending when the wait gave up.
    pub(crate) timed_out: bool,
}

impl DrainReport {
    /// Lines to print once the terminal is restored; empty when all is well.
    pub(crate) fn messages(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .failures
            .iter()
            .map(|e| format!("fuigo: a settings change was not saved: {e}"))
            .collect();
        if self.timed_out {
            out.push(
                "fuigo: settings changes were still being saved at exit and may not have been"
                    .to_owned(),
            );
        }
        out
    }
}

/// Wait (at most `timeout`) for every write submitted so far to finish, so a
/// quit does not drop a write the user already made, and return what went
/// wrong that nobody else will report. Returns at once when no write was ever
/// queued.
pub(crate) async fn drain(timeout: std::time::Duration) -> DrainReport {
    let started = QUEUE
        .sender
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some();
    let mut report = DrainReport::default();
    if started {
        // FIFO: the marker finishes only after everything queued before it.
        let marker = run(|| Ok(()));
        report.timed_out = tokio::time::timeout(timeout, marker).await.is_err();
        if report.timed_out {
            tracing::warn!(?timeout, "config writes still pending at exit");
        }
    }
    report.failures = PENDING_FAILURES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(_, m)| m.clone())
        .collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// Writes run one at a time, in submission order, even when an earlier one
    /// is slower than a later one.
    #[test]
    fn writes_run_one_at_a_time_in_submission_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let receivers: Vec<_> = (0..20u64)
            .map(|i| {
                let log = log.clone();
                run(move || {
                    log.lock().unwrap().push(format!("start {i}"));
                    // Earlier writes are the slow ones.
                    std::thread::sleep(Duration::from_millis(20u64.saturating_sub(i)));
                    log.lock().unwrap().push(format!("end {i}"));
                    Ok(i)
                })
            })
            .collect();
        let results: Vec<u64> = receivers
            .into_iter()
            .map(|rx| rx.blocking_recv().unwrap().map_err(WriteFailure::acknowledge).unwrap())
            .collect();
        assert_eq!(results, (0..20).collect::<Vec<_>>());
        let log = log.lock().unwrap();
        let want: Vec<String> = (0..20)
            .flat_map(|i| [format!("start {i}"), format!("end {i}")])
            .collect();
        // Other tests may share the worker, but these entries are only ours,
        // and no two of ours may interleave.
        assert_eq!(*log, want);
    }

    /// `drain` returns only after the writes queued before it have finished.
    #[tokio::test]
    async fn drain_waits_for_queued_writes() {
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        let _rx = run(move || {
            std::thread::sleep(Duration::from_millis(100));
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let report = drain(Duration::from_secs(10)).await;
        assert!(done.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!report.timed_out);
    }

    /// A failure is reported at exit unless whoever received it acknowledged
    /// it -- including one that WAS received but never shown (the quit dropped
    /// the task result), and one whose receiver was gone before it arrived.
    #[tokio::test]
    async fn unacknowledged_failures_are_reported_at_drain() {
        let received_not_shown = run(|| -> Result<(), String> { Err("p49-received".into()) });
        let shown = run(|| -> Result<(), String> { Err("p49-shown".into()) });
        drop(run(|| -> Result<(), String> { Err("p49-dropped".into()) }));
        // Received, but the result is dropped before presentation.
        drop(received_not_shown.await.unwrap());
        // Received and presented.
        let msg = shown.await.unwrap().unwrap_err().acknowledge();
        assert_eq!(msg, "p49-shown");
        let report = drain(Duration::from_secs(10)).await;
        let messages = report.messages().join("\n");
        assert!(messages.contains("p49-received"), "{messages}");
        assert!(messages.contains("p49-dropped"), "{messages}");
        assert!(!messages.contains("p49-shown"), "{messages}");
    }

    /// A write the worker could not be started for is not run, and its failure
    /// is held like any other: reported at exit when nobody showed it.
    #[tokio::test]
    async fn a_write_that_could_not_start_is_a_pending_failure() {
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        // A queue of its own whose worker cannot be started, driving the same
        // `run` the global queue uses.
        let queue = WriteQueue {
            sender: Mutex::new(None),
            start: || Err(std::io::Error::other("forced (test)")),
        };
        let rx = queue.run(move || -> Result<(), String> {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        drop(rx);
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst), "must not run unordered");
        let messages = drain(Duration::from_secs(10)).await.messages().join("\n");
        assert!(messages.contains("could not start the config write worker: forced"), "{messages}");
    }

    /// A panicking write does not stop the writes queued after it.
    #[test]
    fn a_panicking_write_does_not_stop_the_queue() {
        let boom = run(|| -> Result<u8, String> { panic!("boom") });
        let after = run(|| Ok(7u8));
        let failure = boom.blocking_recv().unwrap().unwrap_err().acknowledge();
        assert!(failure.contains("panicked"), "{failure}");
        assert_eq!(after.blocking_recv().unwrap().map_err(WriteFailure::acknowledge), Ok(7));
    }
}
