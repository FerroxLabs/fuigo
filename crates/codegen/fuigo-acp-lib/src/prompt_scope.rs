//! Prompt scope (Fuigo 1.0.48, design 1022-grokwarm section A): the (promptId, originPromptId) pair of the work that
//! produced an agent-to-client frame.
//!
//! The pair is bound to the task doing the work ([`PromptScope::scope`]) when the work starts, and the agent-side gateway
//! stamps it into every frame it sends (`_meta.promptId` / `_meta.originPromptId`). This is the one place frames are
//! labelled, so no send site can forget the pair. A frame sent by code running outside any bound scope is session-level
//! by rule: both keys are an explicit `null`. The label is never read from "the prompt running now".

use std::sync::Arc;

use agent_client_protocol as acp;
use serde_json::{Value, value::RawValue};

pub const META_PROMPT_ID: &str = "promptId";
pub const META_ORIGIN_PROMPT_ID: &str = "originPromptId";

/// The (promptId, originPromptId) pair of a piece of work.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromptScope {
    pub prompt_id: Option<String>,
    pub origin_prompt_id: Option<String>,
}

tokio::task_local! {
    static SCOPE: PromptScope;
}

impl PromptScope {
    /// A client prompt: its own root.
    pub fn client(prompt_id: &str) -> Self {
        Self {
            prompt_id: Some(prompt_id.to_string()),
            origin_prompt_id: Some(prompt_id.to_string()),
        }
    }

    /// An internal turn with its own minted id, rooted in `origin` (`None` = not caused by a client prompt).
    pub fn internal(prompt_id: &str, origin: Option<String>) -> Self {
        Self {
            prompt_id: Some(prompt_id.to_string()),
            origin_prompt_id: origin,
        }
    }

    /// Session-level work (no prompt): both ids explicitly `null` on the wire.
    pub fn session() -> Self {
        Self::default()
    }

    /// The scope bound to the running task, if any.
    pub fn current() -> Option<Self> {
        SCOPE.try_with(Clone::clone).ok()
    }

    /// Run `fut` with this scope bound. Every frame `fut` sends carries this pair.
    ///
    /// `fut` is boxed: inline, every wrapper reserves a stack slot the size of the whole future in a debug build, and the
    /// wrapped futures (a turn, a tool call that dispatches hooks) are large enough to overflow the 8 MiB session thread.
    pub fn scope<F: std::future::Future>(
        self,
        fut: F,
    ) -> impl std::future::Future<Output = F::Output> {
        SCOPE.scope(self, Box::pin(fut))
    }

    /// `fut` with the CALLER's scope (if any) bound, for work handed to another task (`tokio::spawn(PromptScope::inherit(f))`):
    /// a task-local does not follow a spawn by itself.
    pub fn inherit<F: std::future::Future>(fut: F) -> impl std::future::Future<Output = F::Output> {
        let scope = Self::current();
        let fut = Box::pin(fut); // heap, as in `scope`
        async move {
            match scope {
                Some(scope) => SCOPE.scope(scope, fut).await,
                None => fut.await,
            }
        }
    }

    /// Write both keys into a frame's `_meta`, `null` where absent, so "session-level" differs from "missing".
    pub fn stamp(&self, meta: &mut serde_json::Map<String, Value>) {
        meta.insert(META_PROMPT_ID.to_string(), opt(&self.prompt_id));
        meta.insert(
            META_ORIGIN_PROMPT_ID.to_string(),
            opt(&self.origin_prompt_id),
        );
    }

    /// Like [`Self::stamp`] but keys the frame already carries win (a frame stamped at its origin, then queued).
    pub fn stamp_missing(&self, meta: &mut serde_json::Map<String, Value>) {
        if !meta.contains_key(META_PROMPT_ID) {
            meta.insert(META_PROMPT_ID.to_string(), opt(&self.prompt_id));
        }
        if !meta.contains_key(META_ORIGIN_PROMPT_ID) {
            meta.insert(
                META_ORIGIN_PROMPT_ID.to_string(),
                opt(&self.origin_prompt_id),
            );
        }
    }
}

fn opt(id: &Option<String>) -> Value {
    id.clone().map_or(Value::Null, Value::String)
}

/// Stamp the bound scope's pair into a `_meta` map (keys present win), only when a scope is bound: for MCP
/// `tools/call` params (design A7), which leave through rmcp rather than the gateway.
pub fn stamp_if_bound(meta: &mut serde_json::Map<String, Value>) {
    if let Some(scope) = PromptScope::current() {
        scope.stamp_missing(meta);
    }
}

/// The pair a frame sent now carries: the scope bound to this task, else session-level `null`s.
fn sending_scope() -> PromptScope {
    PromptScope::current().unwrap_or_default()
}

/// Stamp a typed frame's `_meta` (keys already present win).
pub(crate) fn stamp_meta(meta: &mut Option<acp::Meta>) {
    sending_scope().stamp_missing(meta.get_or_insert_with(acp::Meta::new));
}

/// Stamp an extension frame's raw params object (`params._meta`, keys already present win). Everything else in the
/// params is kept byte for byte: the pair is spliced into the text, never re-serialized. A params value that is not a
/// JSON object is left as it is.
pub(crate) fn stamp_params(params: &mut Arc<RawValue>) {
    if let Some(stamped) = spliced(params.get(), &sending_scope()) {
        *params = Arc::from(stamped);
    }
}

fn spliced(text: &str, scope: &PromptScope) -> Option<Box<RawValue>> {
    #[derive(serde::Deserialize)]
    struct Top<'a> {
        #[serde(rename = "_meta", borrow)]
        meta: Option<&'a RawValue>,
    }
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let top: Top<'_> = serde_json::from_str(text).ok()?;
    let pair = |has_prompt: bool, has_origin: bool| {
        let mut out = String::new();
        if !has_prompt {
            out.push_str(&format!("\"{META_PROMPT_ID}\":{}", opt(&scope.prompt_id)));
        }
        if !has_origin {
            if !out.is_empty() {
                out.push(',');
            }
            out.push_str(&format!(
                "\"{META_ORIGIN_PROMPT_ID}\":{}",
                opt(&scope.origin_prompt_id)
            ));
        }
        out
    };
    // Insert `insert` right after the `{` at byte `open` of `text`, with a comma when that object is not empty.
    let splice_at = |open: usize, insert: &str| {
        let rest = &text[open + 1..];
        let sep = if rest.trim_start().starts_with('}') {
            ""
        } else {
            ","
        };
        format!("{}{insert}{sep}{rest}", &text[..=open])
    };
    let out = match top.meta {
        None => splice_at(
            text.len() - trimmed.len(),
            &format!("\"_meta\":{{{}}}", pair(false, false)),
        ),
        Some(meta) => {
            let keys: serde_json::Map<String, Value> = serde_json::from_str(meta.get()).ok()?;
            let insert = pair(
                keys.contains_key(META_PROMPT_ID),
                keys.contains_key(META_ORIGIN_PROMPT_ID),
            );
            if insert.is_empty() {
                return None;
            }
            // `meta` borrows from `text`: its offset is where its `{` is.
            let open = meta.get().as_ptr() as usize - text.as_ptr() as usize;
            splice_at(open, &insert)
        }
    };
    RawValue::from_string(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamped(text: &str, scope: Option<PromptScope>) -> String {
        let mut params: Arc<RawValue> = Arc::from(RawValue::from_string(text.to_string()).unwrap());
        match scope {
            Some(s) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                rt.block_on(s.scope(async { stamp_params(&mut params) }));
            }
            None => stamp_params(&mut params),
        }
        params.get().to_string()
    }

    #[test]
    fn ext_params_get_the_pair_spliced_and_keep_every_other_byte() {
        assert_eq!(
            stamped(r#"{"a": 1}"#, Some(PromptScope::client("p1"))),
            r#"{"_meta":{"promptId":"p1","originPromptId":"p1"},"a": 1}"#
        );
        assert_eq!(
            stamped(r#"{}"#, None),
            r#"{"_meta":{"promptId":null,"originPromptId":null}}"#
        );
        // `_meta` present: the pair joins it, caller keys win.
        assert_eq!(
            stamped(
                r#"{"x":2,"_meta":{"promptId":"d1","k":true}}"#,
                Some(PromptScope::client("p2"))
            ),
            r#"{"x":2,"_meta":{"originPromptId":"p2","promptId":"d1","k":true}}"#
        );
        assert_eq!(
            stamped(r#"{"_meta": { }}"#, Some(PromptScope::internal("n1", None))),
            r#"{"_meta": {"promptId":"n1","originPromptId":null }}"#
        );
        // Both keys present: untouched. Not an object: untouched.
        let both = r#"{"_meta":{"promptId":null,"originPromptId":null}}"#;
        assert_eq!(stamped(both, Some(PromptScope::client("p"))), both);
        assert_eq!(stamped("[1,2]", Some(PromptScope::client("p"))), "[1,2]");
        // A nested `_meta` is not the frame's.
        assert_eq!(
            stamped(r#"{"u":{"_meta":{}}}"#, None),
            r#"{"_meta":{"promptId":null,"originPromptId":null},"u":{"_meta":{}}}"#
        );
    }

    #[tokio::test]
    async fn typed_meta_is_stamped_from_the_bound_scope_and_keeps_caller_keys() {
        let mut meta = None;
        stamp_meta(&mut meta);
        assert_eq!(meta.as_ref().unwrap()[META_PROMPT_ID], Value::Null);
        let mut meta = Some(acp::Meta::from_iter([(
            META_PROMPT_ID.to_string(),
            Value::from("d1"),
        )]));
        PromptScope::client("p2")
            .scope(async { stamp_meta(&mut meta) })
            .await;
        let meta = meta.unwrap();
        assert_eq!(meta[META_PROMPT_ID], "d1");
        assert_eq!(meta[META_ORIGIN_PROMPT_ID], "p2");
    }

    /// A future holding 64 KiB across an await, like a turn or a hook-dispatching tool call (much smaller than those).
    async fn large_future() -> usize {
        let buf = [7u8; 64 * 1024];
        std::future::ready(()).await;
        buf.iter().map(|b| usize::from(*b)).sum()
    }

    #[test]
    fn scope_and_inherit_hold_the_wrapped_future_on_the_heap() {
        // A debug build reserves a stack slot per wrapper the size of what it holds: inline, the scope wrappers around a
        // turn future overflowed the 8 MiB session thread on a hook-dispatching tool call (1.0.48 gate, gdb).
        assert!(std::mem::size_of_val(&large_future()) >= 64 * 1024);
        let scoped = PromptScope::client("p").scope(large_future());
        assert!(
            std::mem::size_of_val(&scoped) < 1024,
            "scope embeds the future: {} bytes",
            std::mem::size_of_val(&scoped)
        );
        let inherited = PromptScope::inherit(large_future());
        assert!(
            std::mem::size_of_val(&inherited) < 1024,
            "inherit embeds the future: {} bytes",
            std::mem::size_of_val(&inherited)
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert_eq!(rt.block_on(scoped), 7 * 64 * 1024);
        assert_eq!(rt.block_on(inherited), 7 * 64 * 1024);
    }

    #[tokio::test]
    async fn inherit_carries_the_callers_scope_into_a_spawned_task() {
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                // The handle is awaited outside the scope: only `inherit` carries the pair into the task.
                let handle = PromptScope::client("p1")
                    .scope(async {
                        let handle = tokio::task::spawn_local(PromptScope::inherit(async {
                            PromptScope::current()
                        }));
                        Some(handle)
                    })
                    .await
                    .expect("spawned");
                let seen = handle.await.unwrap();
                assert_eq!(seen, Some(PromptScope::client("p1")));
                let bare = tokio::task::spawn_local(PromptScope::inherit(async {
                    PromptScope::current()
                }))
                .await
                .unwrap();
                assert_eq!(bare, None);
            })
            .await;
    }
}
