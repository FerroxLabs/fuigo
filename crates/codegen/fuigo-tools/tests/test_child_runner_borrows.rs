//! P122 (P101): a `ChildRunner` need not be `'static`.
//!
//! The shell's runner holds a lifetime-branded `LocalRef<'a, MvpAgent>`, a reference that is valid only while the
//! agent's bound task is. That needs the coordinator to accept a runner (and the futures it returns) that borrow, as
//! `FuturesUnordered` already lets it: nothing is ever spawned. This test compiles and runs a coordinator over a runner
//! that borrows a local, which the former `ChildRunner: 'static` bound refused.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;

use fuigo_tools::implementations::fuigo_build::task::backend::{ChannelBackend, SubagentBackend};
use fuigo_tools::implementations::fuigo_build::task::coordinator::{
    ChildCompletion, ChildControl, ChildRunOutput, ChildRunRequest, ChildRunner, CoordinatorConfig,
    SubagentCoordinator, SubagentProgress,
};
use fuigo_tools::implementations::fuigo_build::task::types::{
    SubagentDescribeOutcome, SubagentValidateTypeOutcome,
};

struct NoControl;

impl ChildControl for NoControl {
    type ProgressFuture = std::future::Ready<SubagentProgress>;

    fn progress(&self) -> Self::ProgressFuture {
        std::future::ready(SubagentProgress::default())
    }

    fn cancel(&self) {}
}

/// Borrows a counter from the test's stack: not `'static`.
struct BorrowingRunner<'a> {
    validations: &'a Cell<usize>,
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

impl<'a> ChildRunner for BorrowingRunner<'a> {
    type Control = NoControl;
    type CompletionData = ();
    type RunFuture = Boxed<'a, ChildRunOutput<()>>;
    type ValidateFuture = Boxed<'a, SubagentValidateTypeOutcome>;
    type DescribeFuture = Boxed<'a, SubagentDescribeOutcome>;

    fn run(&self, _run: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        Box::pin(std::future::pending())
    }

    fn validate_type(&self, _subagent_type: String, _parent: String) -> Self::ValidateFuture {
        let validations = self.validations;
        Box::pin(async move {
            validations.set(validations.get() + 1);
            SubagentValidateTypeOutcome::Ok
        })
    }

    fn describe_type(
        &self,
        _subagent_type: String,
        _harness_agent_type: Option<String>,
        _parent: String,
    ) -> Self::DescribeFuture {
        Box::pin(std::future::ready(SubagentDescribeOutcome::Unavailable))
    }

    fn on_completed(&self, _completion: ChildCompletion<()>) {}
}

#[tokio::test(flavor = "current_thread")]
async fn a_coordinator_serves_a_runner_that_borrows_from_its_caller() {
    let validations = Cell::new(0);
    let (command_tx, command_rx) = SubagentCoordinator::<BorrowingRunner<'_>>::channel();
    let coordinator = SubagentCoordinator::from_channel(
        command_rx,
        BorrowingRunner {
            validations: &validations,
        },
        CoordinatorConfig::default(),
    );
    let backend = ChannelBackend::from_coordinator(command_tx);
    let outcome = tokio::select! {
        () = coordinator.run() => panic!("the coordinator stopped while its backend was alive"),
        outcome = backend.validate_type("explore", "parent") => outcome,
    };
    assert!(matches!(outcome, SubagentValidateTypeOutcome::Ok), "{outcome:?}");
    assert_eq!(validations.get(), 1, "the borrowing runner served the validation");
}
