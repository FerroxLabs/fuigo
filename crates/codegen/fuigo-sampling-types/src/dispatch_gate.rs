//! Local-only gate awaited right before a model HTTP request is dispatched; never sent to a provider.
use std::{future::Future, pin::Pin};

/// A boxed future that resolves once the gate is open.
pub type DispatchGateFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Holds model dispatch while the owner (a parked session) wants no request to leave the process.
pub trait DispatchGate: Send + Sync {
    /// A terminal prompt rejects dispatch rather than waiting for another user prompt.
    fn check_open(&self) -> crate::Result<()> { Ok(()) }
    /// Observe a model refusal at the HTTP boundary, before any retry can dispatch.
    /// Return true when this prompt has spent its one refresh exception.
    fn on_refusal(&self, _error: &crate::SamplingError) -> bool { false }
    /// Resolves when a request may be dispatched.
    fn wait_open(&self) -> DispatchGateFuture<'_>;
}
