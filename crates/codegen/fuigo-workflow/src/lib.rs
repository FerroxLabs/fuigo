pub mod engine;
pub mod host;
pub mod journal;
pub mod meta;
pub mod run;
pub mod validate;

pub const MAX_WORKFLOW_NAME_LEN: usize = 64;
pub const MAX_WORKFLOW_DESCRIPTION_LEN: usize = 1_024;
pub const MAX_WORKFLOW_WHEN_TO_USE_LEN: usize = 2_048;
pub const MAX_WORKFLOW_PHASES: usize = 64;
pub const MAX_PHASE_TITLE_LEN: usize = 128;
pub const MAX_PHASE_DETAIL_LEN: usize = 1_024;
pub const MAX_PARALLEL: usize = 1_024;
pub const DEFAULT_AGENT_BUDGET: u64 = 128;
pub const MAX_AGENT_BUDGET: u64 = 1_024;
pub const MAX_HOST_CALLS: u64 = 10_000;

pub(crate) fn with_rhai_hint(msg: String) -> String {
    let hint = if msg.contains("Expression exceeds maximum complexity") {
        "a single expression nests too deep — usually one long chained `+` string \
         concatenation. Split it into multiple `+=` statements."
    } else if msg.contains("reserved keyword") {
        "Rhai reserves identifiers it doesn't use — `shared`, `sync`, `async`, `await`, \
         `spawn`, `go`, `thread`, `new`, `match`, `case`, `default`, `void`, `null`, \
         `nil`, `exit`, `static`, `var` — rename the variable (`shared` → `has_shared`)."
    } else if msg.contains("getter is not registered for type 'char'") {
        "indexing a string yields a `char`, so field access on it fails — you likely \
         indexed a string you expected to be an array (e.g. unparsed JSON in an agent \
         output). Check with `type_of(x)`; slice strings with `s.sub_string(start, len)`."
    } else {
        return msg;
    };
    format!("{msg}\nhint: {hint}")
}

/// Route a script's `print(..)` / `debug(..)` to tracing.
///
/// rhai's default handlers write them to the process stdout with `println!`, which panics when
/// stdout is a dead pipe or a full disk (SIGABRT under `panic = "abort"`, R077) and otherwise
/// lands in the TUI's terminal or a headless run's protocol stream.
pub(crate) fn route_script_output(engine: &mut rhai::Engine) {
    engine.on_print(|text| tracing::info!(target: "fuigo_workflow::script", "{text}"));
    engine.on_debug(|text, source, position| {
        tracing::debug!(
            target: "fuigo_workflow::script",
            source = source.unwrap_or(""),
            position = %position,
            "{text}"
        )
    });
}

pub use engine::{WorkflowRunParams, run_workflow};
pub use host::{AgentOpts, AgentResult, BudgetState, HostError, WorkflowHostRequest};
pub use journal::{Journal, JournalEntry, JournalError};
pub use meta::{MetaError, PhaseMeta, WorkflowMeta, extract_meta};
pub use run::{PauseKind, WorkflowOutcome};
pub use validate::{
    ValidationError, ValidationReport, validate_script, validate_script_with_agent_budget,
    validate_script_with_cancel,
};

#[cfg(test)]
mod script_output_tests {
    use std::sync::{Arc, Mutex};

    /// Collects the `message` of every event.
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Message<'a>(&'a mut Vec<String>);
            impl tracing::field::Visit for Message<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0.push(format!("{value:?}"));
                    }
                }
            }
            event.record(&mut Message(&mut self.0.lock().unwrap()));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// `print` and `debug` reach tracing, so rhai's stdout default (a `println!`) is not in use.
    #[test]
    fn script_print_and_debug_go_to_tracing_not_stdout() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(Capture(seen.clone()), || {
            let mut engine = rhai::Engine::new();
            super::route_script_output(&mut engine);
            engine
                .run(r#"print("p75-print"); debug("p75-debug");"#)
                .expect("script runs");
        });
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|m| m.contains("p75-print")), "{seen:?}");
        assert!(seen.iter().any(|m| m.contains("p75-debug")), "{seen:?}");
    }
}
