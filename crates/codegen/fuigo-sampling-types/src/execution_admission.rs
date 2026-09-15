//! Local-only durable admission capability; never sent to a provider.
use crate::RequestPurpose;
use std::{future::Future, pin::Pin};

pub type AdmissionFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub trait ExecutionAdmission: std::fmt::Debug + Send + Sync {
    fn scope_id(&self) -> &str;
    /// Remaining time on the original durable deadline, not a renewed timeout.
    fn remaining_time(&self) -> Option<std::time::Duration> {
        None
    }
    /// Durably debit before transport; unknown effects are never refunded.
    fn admit(&self, purpose: RequestPurpose, attempt_id: String) -> AdmissionFuture<'_>;
    /// Record a definitive completed attempt without refunding its debit.
    fn settle(&self, attempt_id: String, usage: Option<crate::TokenUsage>) -> AdmissionFuture<'_>;
    /// Settle an attempt a resend has taken over: the retry carries the same logical
    /// call forward, so the attempt is finished work, not unresolved work. Its call
    /// debit is never refunded, and any usage it did report is still charged.
    /// Defaults to [`ExecutionAdmission::settle`].
    fn supersede(
        &self,
        attempt_id: String,
        usage: Option<crate::TokenUsage>,
    ) -> AdmissionFuture<'_> {
        self.settle(attempt_id, usage)
    }
    /// Mark a finished attempt no resend has taken over: it stays unresolved work (a
    /// partial terminal receipt) unless the caller that owns the logical call resubmits
    /// it, which supersedes every attempt marked this way (the shell's transient-retry,
    /// auth and rate-limit resubmits do exactly that).
    /// Defaults to a no-op, which keeps the attempt unresolved.
    fn abandon(&self, _attempt_id: String) -> AdmissionFuture<'_> {
        Box::pin(async { Ok(()) })
    }
}
