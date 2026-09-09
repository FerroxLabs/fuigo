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
}
