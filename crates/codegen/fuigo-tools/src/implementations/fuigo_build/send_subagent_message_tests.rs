use pretty_assertions::assert_eq;

use super::*;
use crate::implementations::fuigo_build::task::backend::ChannelBackend;
use crate::implementations::fuigo_build::task::coordinator::{
    ChildCompletion, ChildControl, ChildRunOutput, ChildRunRequest, ChildRunner, SendBoxFuture,
    SubagentCoordinator, SubagentCoordinatorReceiver, SubagentProgress,
};
use crate::implementations::fuigo_build::task::types::{
    ActiveAgentMessageOperation, ActiveAgentMessageOutcome, MAX_ACTIVE_AGENT_MESSAGE_BYTES,
    SubagentDepthCounter, SubagentDescribeOutcome, SubagentValidateTypeOutcome,
};
use crate::types::resources::{Resources, SharedResources};
use crate::types::tool_metadata::test_ctx;

const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn completes<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TEST_TIMEOUT, future)
        .await
        .expect("send_subagent_message test operation timed out")
}

struct ToolTestControl;

impl ChildControl for ToolTestControl {
    type ProgressFuture = std::future::Ready<SubagentProgress>;

    fn progress(&self) -> Self::ProgressFuture {
        std::future::ready(SubagentProgress::default())
    }

    fn cancel(&self) {}
}

struct ToolTestRunner;

impl ChildRunner for ToolTestRunner {
    type Control = ToolTestControl;
    type CompletionData = ();
    type RunFuture = SendBoxFuture<ChildRunOutput<()>>;
    type ValidateFuture = SendBoxFuture<SubagentValidateTypeOutcome>;
    type DescribeFuture = SendBoxFuture<SubagentDescribeOutcome>;

    fn run(&self, _: ChildRunRequest<Self::Control>) -> Self::RunFuture {
        Box::pin(std::future::pending())
    }

    fn validate_type(&self, _: String, _: String) -> Self::ValidateFuture {
        Box::pin(std::future::pending())
    }

    fn describe_type(&self, _: String, _: Option<String>, _: String) -> Self::DescribeFuture {
        Box::pin(std::future::pending())
    }

    fn on_completed(&self, _: ChildCompletion<Self::CompletionData>) {}
}

fn coordinator_backend() -> (ChannelBackend, SubagentCoordinatorReceiver) {
    let (sender, receiver) = SubagentCoordinator::<ToolTestRunner>::channel();
    (
        ChannelBackend::for_coordinator_session(sender, "trusted-parent"),
        receiver,
    )
}

fn resources_with_backend(backend: ChannelBackend) -> Resources {
    let mut resources = Resources::new();
    resources.insert(backend.into_resource());
    resources.insert(SubagentDepthCounter(0));
    resources
}

async fn run_with_delivery(
    resources: SharedResources,
    subagent_id: &str,
    text: String,
    delivery: Option<SendSubagentMessageDelivery>,
) -> SendSubagentMessageOutput {
    completes(fuigo_tool_runtime::Tool::run(
        &SendSubagentMessageTool,
        test_ctx(resources),
        SendSubagentMessageInput {
            subagent_id: subagent_id.to_owned(),
            text,
            delivery,
        },
    ))
    .await
    .unwrap()
}

async fn run(
    resources: SharedResources,
    subagent_id: &str,
    text: String,
) -> SendSubagentMessageOutput {
    run_with_delivery(resources, subagent_id, text, None).await
}

async fn backend_operation(
    delivery: Option<SendSubagentMessageDelivery>,
) -> ActiveAgentMessageOperation {
    let (backend, mut receiver) = coordinator_backend();
    let send = run_with_delivery(
        resources_with_backend(backend).into_shared(),
        "sub-1",
        "follow up".to_owned(),
        delivery,
    );
    let respond = async move {
        let ingress = completes(receiver.active_messages.recv())
            .await
            .expect("expected active-message ingress");
        let operation = ingress.request.request.operation();
        ingress
            .request
            .respond_to
            .send(ActiveAgentMessageOutcome::Accepted {
                message_id: "message-1".to_owned(),
            })
            .unwrap();
        operation
    };
    completes(async { tokio::join!(send, respond) }).await.1
}

async fn run_backend_outcome(outcome: ActiveAgentMessageOutcome) -> SendSubagentMessageOutput {
    let (backend, mut receiver) = coordinator_backend();
    let send = run(
        resources_with_backend(backend).into_shared(),
        "sub-1",
        "follow up".to_owned(),
    );
    let respond = async move {
        let ingress = completes(receiver.active_messages.recv())
            .await
            .expect("expected active-message ingress");
        ingress.request.respond_to.send(outcome).unwrap();
    };
    completes(async { tokio::join!(send, respond) }).await.0
}

#[test]
fn required_input_keys_are_semantically_pinned() {
    let schema = crate::registry::types::generate_schema::<SendSubagentMessageInput>();
    let mut required = schema["required"]
        .as_array()
        .expect("required keys")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    required.sort_unstable();
    assert_eq!(required, ["subagent_id", "text"]);
    assert!(
        schema
            .pointer("/properties/delivery")
            .is_some_and(serde_json::Value::is_object)
    );
}

#[test]
fn delivery_values_are_a_closed_snake_case_set() {
    let values = [
        SendSubagentMessageDelivery::Steer,
        SendSubagentMessageDelivery::Queue,
        SendSubagentMessageDelivery::Interject,
    ]
    .map(|value| serde_json::to_value(value).expect("serialize delivery"));
    assert_eq!(values, ["steer", "queue", "interject"]);
}

#[test]
fn unknown_delivery_value_fails_to_deserialize() {
    let error = serde_json::from_value::<SendSubagentMessageInput>(serde_json::json!({
        "subagent_id": "sub-1",
        "text": "follow up",
        "delivery": "urgent",
    }))
    .expect_err("an unknown delivery must fail closed");
    assert!(
        error.to_string().contains("unknown variant `urgent`"),
        "{error}"
    );
}

#[test]
fn wire_delivery_resolves_to_the_operation() {
    let parse = |raw: serde_json::Value| {
        serde_json::from_value::<SendSubagentMessageInput>(raw)
            .expect("valid input")
            .operation()
    };
    assert_eq!(
        parse(serde_json::json!({"subagent_id": "a", "text": "t", "delivery": "interject"})),
        ActiveAgentMessageOperation::Interject
    );
    assert_eq!(
        parse(serde_json::json!({"subagent_id": "a", "text": "t", "delivery": "steer"})),
        ActiveAgentMessageOperation::Steer
    );
    assert_eq!(
        parse(serde_json::json!({"subagent_id": "a", "text": "t", "delivery": "queue"})),
        ActiveAgentMessageOperation::Queue
    );
    // Omitted keeps the class every send carried before the field existed.
    assert_eq!(
        parse(serde_json::json!({"subagent_id": "a", "text": "t"})),
        ActiveAgentMessageOperation::Queue
    );
}

#[tokio::test]
async fn omitted_delivery_reaches_the_backend_as_queue() {
    assert_eq!(
        ActiveAgentMessageOperation::Queue,
        backend_operation(None).await
    );
}

#[tokio::test]
async fn delivery_steer_reaches_the_backend_as_steer() {
    assert_eq!(
        ActiveAgentMessageOperation::Steer,
        backend_operation(Some(SendSubagentMessageDelivery::Steer)).await
    );
}

#[tokio::test]
async fn delivery_interject_reaches_the_backend_as_interject() {
    assert_eq!(
        ActiveAgentMessageOperation::Interject,
        backend_operation(Some(SendSubagentMessageDelivery::Interject)).await
    );
}

/// The shipped description is a promise to the model, and Fuigo implements ONE
/// delivery for all three classes (see `description_template`'s invariant).
/// This pins the promise to the implementation: the golden text below is the
/// exact string the model receives, and it may not claim a per-class
/// mechanism this engine does not have.
#[test]
fn tool_description_promises_only_the_delivery_the_engine_implements() {
    const SHIPPED: &str = "Send a follow-up message to a subagent owned by this session. An active subagent receives it as a message; an eligible completed subagent (not cancelled, not workflow-owned, and one whose completion reports to this session) resumes with the same identity and runs the text as its next turn, reporting like a background completion. `delivery` (`queue` by default, `steer`, `interject`) records how you mean the message and is named on its row in the transcript; it does not change how the message lands. Every class lands the same way here: an active subagent's message joins the turn it is running at that turn's next safe point, interrupting it if it is blocked waiting on background work, and starts a turn of its own if the subagent is idle. Do not pick a class expecting a different arrival order or a different priority.";

    let ctx = fuigo_tool_runtime::ListToolsContext::new();
    let shipped = fuigo_tool_runtime::Tool::description(&SendSubagentMessageTool, &ctx);
    assert_eq!(shipped.description, SHIPPED);

    // The one delivery the engine implements is stated, and stated as the one.
    assert!(SHIPPED.contains("it does not change how the message lands"));
    assert!(SHIPPED.contains("Every class lands the same way here"));
    assert!(SHIPPED.contains("at that turn's next safe point"));
    assert!(SHIPPED.contains("interrupting it if it is blocked waiting on background work"));

    // Upstream's per-class promises, which this engine does not keep. Each of
    // these is a claim that one class arrives differently from another; none
    // may return without the engine that backs it.
    for unkept in [
        "ahead of pending steers",
        "waits as a later turn",
        "is urgent",
        "at the earliest safe point",
        "selects how the message lands",
    ] {
        assert!(
            !SHIPPED.contains(unkept),
            "tool description promises `{unkept}`, which the engine does not implement"
        );
    }

    // The per-variant schema descriptions ship to the model too — and this
    // reads the SHIPPING schema, not `schemars::schema_for!`. What the model
    // receives is `registry::types::generate_schema` (draft07,
    // `inline_subschemas`, root `title`/`description` stripped), the same call
    // `register_tool` and `ToolConfig` make; `schema_for!` would be a
    // different generator with a different dialect.
    let schema = crate::registry::types::generate_schema::<SendSubagentMessageInput>();
    let schema_text = schema.to_string();
    for unkept in [
        "ahead of pending steers",
        "Join the current turn",
        "Wait as a later turn",
        "Delivery operation",
    ] {
        assert!(
            !schema_text.contains(unkept),
            "delivery schema promises `{unkept}`, which the engine does not implement"
        );
    }
    assert!(schema_text.contains("it does not change how the message lands"));
}

#[test]
fn tool_capabilities_are_write_scoped() {
    let capabilities = fuigo_tool_runtime::Tool::capabilities(&SendSubagentMessageTool);
    assert!(!capabilities.is_read_only);
    assert_eq!(
        capabilities.tool_scope,
        Some(fuigo_tool_protocol::ToolScope::Write)
    );
}

#[tokio::test]
async fn accepted_roundtrip_uses_backend_bound_parent_and_preserves_request() {
    let (backend, mut receiver) = coordinator_backend();
    let send = run(
        resources_with_backend(backend).into_shared(),
        "sub-1",
        "follow up".to_owned(),
    );
    let respond = async move {
        let ingress = completes(receiver.active_messages.recv())
            .await
            .expect("expected active-message ingress");
        assert_eq!(ingress.request.parent_session_id, "trusted-parent");
        assert_eq!(ingress.request.request.subagent_id(), "sub-1");
        assert_eq!(ingress.request.request.text().as_ref(), "follow up");
        ingress
            .request
            .respond_to
            .send(ActiveAgentMessageOutcome::Accepted {
                message_id: "message-1".to_owned(),
            })
            .unwrap();
    };

    assert_eq!(
        completes(async { tokio::join!(send, respond) }).await.0,
        SendSubagentMessageOutput::Accepted {
            message_id: "message-1".to_owned()
        }
    );
}

#[tokio::test]
async fn invalid_message_sizes_return_limit_without_calling_backend() {
    let (backend, mut receiver) = coordinator_backend();
    let resources = resources_with_backend(backend).into_shared();

    for (text, expected_observed_bytes) in [
        (String::new(), 0),
        (
            "x".repeat(MAX_ACTIVE_AGENT_MESSAGE_BYTES + 1),
            MAX_ACTIVE_AGENT_MESSAGE_BYTES + 1,
        ),
    ] {
        assert_eq!(
            run(resources.clone(), "sub-1", text).await,
            SendSubagentMessageOutput::Limit {
                max_bytes: MAX_ACTIVE_AGENT_MESSAGE_BYTES,
                observed_bytes: expected_observed_bytes,
            }
        );
        assert!(receiver.active_messages.try_recv().is_err());
    }
}

#[tokio::test]
async fn explicit_root_depth_without_backend_returns_unsupported() {
    let mut resources = Resources::new();
    resources.insert(SubagentDepthCounter(0));
    assert_eq!(
        run(resources.into_shared(), "sub-1", "follow up".to_owned()).await,
        SendSubagentMessageOutput::Unsupported
    );
}

#[tokio::test]
async fn missing_or_nested_depth_returns_unsupported_without_calling_backend() {
    for depth in [None, Some(1)] {
        let (backend, mut receiver) = coordinator_backend();
        let mut resources = Resources::new();
        resources.insert(backend.into_resource());
        if let Some(depth) = depth {
            resources.insert(SubagentDepthCounter(depth));
        }

        assert_eq!(
            run(resources.into_shared(), "sub-1", "follow up".to_owned()).await,
            SendSubagentMessageOutput::Unsupported
        );
        assert!(receiver.active_messages.try_recv().is_err());
    }
}

#[tokio::test]
async fn legacy_ingress_is_unsupported_without_sending_an_event() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let resources =
        resources_with_backend(ChannelBackend::for_session(tx, "trusted-parent")).into_shared();

    assert_eq!(
        run(resources, "sub-1", "follow up".to_owned()).await,
        SendSubagentMessageOutput::Unsupported
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn coordinator_outcomes_map_to_closed_tool_outputs() {
    for (outcome, expected) in [
        (
            ActiveAgentMessageOutcome::NotFoundOrNotOwned,
            SendSubagentMessageOutput::NotFoundOrNotOwned,
        ),
        (
            ActiveAgentMessageOutcome::NotActiveOrFinalizing,
            SendSubagentMessageOutput::NotActiveOrFinalizing,
        ),
        (
            ActiveAgentMessageOutcome::NotAcceptedBeforeDeadline,
            SendSubagentMessageOutput::NotAcceptedBeforeDeadline,
        ),
        (
            ActiveAgentMessageOutcome::Unsupported,
            SendSubagentMessageOutput::Unsupported,
        ),
        (
            ActiveAgentMessageOutcome::Saturated { max_in_flight: 64 },
            SendSubagentMessageOutput::Saturated { max_in_flight: 64 },
        ),
        (
            ActiveAgentMessageOutcome::Limit {
                max_bytes: 7,
                observed_bytes: 9,
            },
            SendSubagentMessageOutput::Limit {
                max_bytes: 7,
                observed_bytes: 9,
            },
        ),
    ] {
        assert_eq!(run_backend_outcome(outcome).await, expected);
    }
}

#[tokio::test]
async fn dropped_coordinator_response_maps_to_definite_channel_closure() {
    let (backend, mut receiver) = coordinator_backend();
    let send = run(
        resources_with_backend(backend).into_shared(),
        "sub-1",
        "follow up".to_owned(),
    );
    let drop_response = async move {
        let ingress = completes(receiver.active_messages.recv())
            .await
            .expect("expected active-message ingress");
        drop(ingress);
    };

    assert_eq!(
        completes(async { tokio::join!(send, drop_response) })
            .await
            .0,
        SendSubagentMessageOutput::ChannelClosed
    );
}

#[test]
fn disposition_classification_is_closed() {
    use SendSubagentMessageDisposition as Disposition;

    for (output, expected) in [
        (
            SendSubagentMessageOutput::Accepted {
                message_id: "message-1".into(),
            },
            Disposition::Accepted,
        ),
        (
            SendSubagentMessageOutput::NotFoundOrNotOwned,
            Disposition::Rejected,
        ),
        (
            SendSubagentMessageOutput::NotActiveOrFinalizing,
            Disposition::Rejected,
        ),
        (
            SendSubagentMessageOutput::Saturated { max_in_flight: 8 },
            Disposition::Rejected,
        ),
        (
            SendSubagentMessageOutput::NotAcceptedBeforeDeadline,
            Disposition::Rejected,
        ),
        (
            SendSubagentMessageOutput::Unsupported,
            Disposition::Rejected,
        ),
        (
            SendSubagentMessageOutput::Limit {
                max_bytes: 8,
                observed_bytes: 9,
            },
            Disposition::Rejected,
        ),
        (
            SendSubagentMessageOutput::AdmissionUncertain,
            Disposition::Unconfirmed,
        ),
        (
            SendSubagentMessageOutput::ChannelClosed,
            Disposition::Rejected,
        ),
    ] {
        assert_eq!(output.disposition(), expected);
    }
}

#[test]
fn uncertain_display_string_does_not_claim_failure_or_success() {
    let display = SendSubagentMessageOutput::AdmissionUncertain
        .to_string()
        .to_ascii_lowercase();
    assert!(display.contains("could not be confirmed"));
    assert!(display.contains("may or may not have been accepted"));
    assert!(!display.contains("failed"));
    assert!(!display.contains("succeeded"));
}

#[test]
fn proved_rejection_strings_do_not_claim_uncertainty() {
    for output in [
        SendSubagentMessageOutput::NotAcceptedBeforeDeadline,
        SendSubagentMessageOutput::ChannelClosed,
    ] {
        let display = output.to_string().to_ascii_lowercase();
        assert!(display.contains("not accepted"));
        assert!(!display.contains("may or may not"));
    }
}

#[tokio::test]
async fn closed_coordinator_ingress_maps_to_channel_closed() {
    let (backend, receiver) = coordinator_backend();
    drop(receiver);

    assert_eq!(
        run(
            resources_with_backend(backend).into_shared(),
            "sub-1",
            "follow up".to_owned(),
        )
        .await,
        SendSubagentMessageOutput::ChannelClosed
    );
}
