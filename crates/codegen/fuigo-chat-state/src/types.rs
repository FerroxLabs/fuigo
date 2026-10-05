//! Shared domain types for the chat state actor.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use fuigo_sampling_types::{ConversationItem, SamplingConfig};

/// The bare, UN-nonced memory-context tag. Fuigo no longer emits it: anyone can
/// write this literal (a repo's AGENTS.md, a file name, a tool result), so it is
/// never treated as the boundary of a Fuigo-inserted block. Blocks Fuigo inserts
/// carry a nonce in both tags; see [`memory_context_open_tag`].
pub const MEMORY_CONTEXT_OPEN_TAG: &str = "<memory-context>";

/// Bare closing tag paired with [`MEMORY_CONTEXT_OPEN_TAG`]; untrusted as well.
pub const MEMORY_CONTEXT_CLOSE_TAG: &str = "</memory-context>";

const MEMORY_CONTEXT_NONCED_OPEN_PREFIX: &str = "<memory-context nonce=\"";

/// Opening tag of a memory-context block that Fuigo inserted. The nonce is a
/// random value private to this Fuigo installation, so text that was written
/// before the session (a repo's rule files) cannot produce a matching pair.
/// Shared by the emitter in `fuigo-shell` and the upsert here.
pub fn memory_context_open_tag(nonce: &str) -> String {
    format!("{MEMORY_CONTEXT_NONCED_OPEN_PREFIX}{nonce}\">")
}

/// Closing tag paired with [`memory_context_open_tag`] for the same nonce.
pub fn memory_context_close_tag(nonce: &str) -> String {
    format!("</memory-context nonce=\"{nonce}\">")
}

/// The nonce of a block that STARTS with a nonced opening tag, if any.
pub fn memory_context_block_nonce(block: &str) -> Option<&str> {
    let rest = block.strip_prefix(MEMORY_CONTEXT_NONCED_OPEN_PREFIX)?;
    let end = rest.find("\">")?;
    let nonce = &rest[..end];
    (!nonce.is_empty() && nonce.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(nonce)
}

/// Byte range of the first complete block with this nonce at or after `from`:
/// a closing tag and the LAST opening tag before it (so a stray, unclosed opening
/// tag earlier in the text is never paired with a later block's close and the
/// text between them is never part of the range). `None` when there is no
/// opening tag followed by a closing tag; callers must then keep the text
/// unchanged, never cut it at an opening tag.
pub fn find_memory_context_block(
    text: &str,
    nonce: &str,
    from: usize,
) -> Option<std::ops::Range<usize>> {
    let open = memory_context_open_tag(nonce);
    let close = memory_context_close_tag(nonce);
    let first_open = from + text.get(from..)?.find(&open)?;
    let close_at = first_open + text[first_open..].find(&close)?;
    let start = first_open + text[first_open..close_at].rfind(&open)?;
    Some(start..close_at + close.len())
}

/// Configuration for the ChatStateActor at spawn time.
#[derive(Debug, Clone)]
pub struct ChatStateConfig {
    /// Initial conversation items to populate the state with.
    pub initial_conversation: Vec<ConversationItem>,
    /// Sampling configuration (model, context window, etc.).
    pub sampling_config: SamplingConfig,
}

/// Immutable snapshot of the actor's state (for forking, rewind).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatStateSnapshot {
    /// The full conversation history.
    pub conversation: Vec<ConversationItem>,
    /// Current sampling configuration.
    pub sampling_config: SamplingConfig,
    /// Current prompt index (incremented per user turn).
    pub prompt_index: usize,
    /// Accumulated token usage.
    pub total_tokens: u64,
    /// Bytes/4 estimate of the conversation as of the last `record_token_usage`.
    /// `0` means unknown (pre-field snapshot); restore re-estimates instead.
    #[serde(default)]
    pub estimate_at_last_response: u64,
    /// File paths the agent has edited.
    pub agent_edited_paths: BTreeSet<String>,
    /// Cached prompt texts for rewind preview.
    pub prompt_texts: Vec<String>,
    /// Timestamp when the current stream started (epoch ms).
    pub stream_start_ms: Option<i64>,
    /// Timestamp when the current turn started (epoch ms).
    pub turn_start_ms: Option<i64>,
    /// Prompt index at which the last compaction occurred.
    pub last_compaction_prompt_index: Option<usize>,
    /// Opaque credential secrets (API key, optional extra auth, client version).
    #[serde(default)]
    pub credentials: Credentials,
}

/// Metadata for session notifications (timing info).
#[derive(Debug, Clone)]
pub struct NotificationMeta {
    /// Timestamp when the current stream started (epoch ms).
    pub stream_start_ms: Option<i64>,
    /// Timestamp when the current turn started (epoch ms).
    pub turn_start_ms: Option<i64>,
}

/// Configuration for tool-result pruning.
///
/// Prunes old, large tool results from the conversation to reclaim context space.
/// Two modes: soft trim (keep head + tail) and hard clear (replace entirely).
#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// Whether pruning is enabled.
    pub enabled: bool,
    /// Number of recent turns whose tool results are never pruned.
    pub keep_last_n_turns: usize,
    /// Character threshold above which old tool results are soft-trimmed.
    pub soft_trim_threshold: usize,
    /// Characters to keep from the start of a soft-trimmed result.
    pub soft_trim_head: usize,
    /// Characters to keep from the end of a soft-trimmed result.
    pub soft_trim_tail: usize,
    /// Turn age after which tool results are hard-cleared (replaced with placeholder).
    pub hard_clear_age_turns: usize,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_last_n_turns: 3,
            soft_trim_threshold: 4000,
            soft_trim_head: 1500,
            soft_trim_tail: 1500,
            hard_clear_age_turns: 10,
        }
    }
}

/// Where the session's current api_key came from.
/// Determines whether the key can be refreshed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// From AuthManager (fuigo login, OIDC, external binary). Refreshable.
    #[default]
    SessionToken,
    /// From user config ([model.*] api_key, env_key, FUIGO_API_KEY). Not refreshable.
    ApiKey,
}

/// Credential/secret fields that the actor stores opaquely.
///
/// These are fields from the shell's full `Config` that aren't part of
/// `fuigo_sampling_types::SamplingConfig` (which is secret-free).
/// The actor just stores and returns them — it never interprets them.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    /// API key for authentication.
    pub api_key: Option<String>,
    /// Whether this is a session token (refreshable) or user-provided api key.
    #[serde(default)]
    pub auth_type: AuthType,
    /// Optional extra auth material forwarded with requests when present.
    pub alpha_test_key: Option<String>,
    /// Client version string.
    pub client_version: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            api_key,
            auth_type,
            alpha_test_key,
            client_version,
        } = self;
        f.debug_struct("Credentials")
            .field("api_key", &api_key.as_ref().map(|_| "<redacted>"))
            .field("auth_type", auth_type)
            .field("alpha_test_key", &alpha_test_key.as_ref().map(|_| "<redacted>"))
            .field("client_version", client_version)
            .finish()
    }
}

/// The messages captured during a single conversation turn.
///
/// Produced by `TakeTurnMessages` after a `BeginTurnCapture`/message-push cycle.
#[derive(Debug, Clone)]
pub struct TurnCapture {
    /// The ordered sequence of messages appended during this turn.
    pub messages: Vec<ConversationItem>,
    /// Whether compaction (conversation replacement) occurred mid-turn.
    pub compaction_occurred: bool,
}

/// Item counts for a conversation, broken down by role.
///
/// Returned by `get_conversation_counts()` — avoids cloning the conversation
/// when only role counts and total length are needed (e.g. for telemetry).
#[derive(Debug, Clone, Default)]
pub struct ConversationCounts {
    /// Total number of items in the conversation.
    pub total: usize,
    /// Number of `User` items.
    pub user: usize,
    /// Number of `Assistant` items.
    pub assistant: usize,
    /// Number of `ToolResult` items.
    pub tool_result: usize,
}

/// Info returned when auto-compact threshold is exceeded.
#[derive(Debug, Clone)]
pub struct AutoCompactTrigger {
    /// Current total token count.
    pub total_tokens: u64,
    /// Model's context window size.
    pub context_window: NonZeroU64,
    /// Current utilization as a percentage (0–100).
    pub utilization_percent: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trips_through_serde_json() {
        let snapshot = ChatStateSnapshot {
            conversation: vec![],
            sampling_config: SamplingConfig {
                base_url: "https://api.example.com".to_string(),
                model: "test-model".to_string(),
                max_completion_tokens: None,
                temperature: None,
                top_p: None,
                max_retries: Some(6),
                api_backend: Default::default(),
                extra_headers: Default::default(),
                query_params: Default::default(),
                env_http_headers: Default::default(),
                context_window: NonZeroU64::new(128_000).unwrap(),
                reasoning_effort: None,
                stream_tool_calls: None,
                mtls_cert_dir: None,
                rate_limit_retry_threshold: None,
                reasoning_summary: None,
            },
            prompt_index: 0,
            total_tokens: 0,
            estimate_at_last_response: 0,
            agent_edited_paths: BTreeSet::new(),
            prompt_texts: vec![],
            stream_start_ms: None,
            turn_start_ms: None,
            last_compaction_prompt_index: None,
            credentials: Credentials::default(),
        };

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let deserialized: ChatStateSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.prompt_index, 0);
        assert_eq!(deserialized.total_tokens, 0);
        assert!(deserialized.conversation.is_empty());
        assert!(deserialized.agent_edited_paths.is_empty());
        assert!(deserialized.last_compaction_prompt_index.is_none());
        assert_eq!(deserialized.sampling_config.max_retries, Some(6));
    }

    #[test]
    fn snapshot_round_trips_with_data() {
        use fuigo_sampling_types::ConversationItem;

        let snapshot = ChatStateSnapshot {
            conversation: vec![
                ConversationItem::system("You are a helpful assistant."),
                ConversationItem::user("Hello!"),
                ConversationItem::assistant("Hi there!"),
            ],
            sampling_config: SamplingConfig {
                base_url: "https://api.example.com".to_string(),
                model: "grok-3".to_string(),
                max_completion_tokens: Some(4096),
                temperature: Some(0.7),
                top_p: None,
                max_retries: None,
                api_backend: Default::default(),
                extra_headers: Default::default(),
                query_params: Default::default(),
                env_http_headers: Default::default(),
                context_window: NonZeroU64::new(128_000).unwrap(),
                reasoning_effort: None,
                stream_tool_calls: None,
                mtls_cert_dir: None,
                rate_limit_retry_threshold: None,
                reasoning_summary: None,
            },
            prompt_index: 5,
            total_tokens: 1234,
            estimate_at_last_response: 900,
            agent_edited_paths: BTreeSet::from([
                "src/main.rs".to_string(),
                "src/lib.rs".to_string(),
            ]),
            prompt_texts: vec!["first prompt".to_string(), "second prompt".to_string()],
            stream_start_ms: Some(1234567890),
            turn_start_ms: Some(1234567800),
            last_compaction_prompt_index: Some(2),
            credentials: Credentials::default(),
        };

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let deserialized: ChatStateSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.prompt_index, 5);
        assert_eq!(deserialized.total_tokens, 1234);
        assert_eq!(deserialized.conversation.len(), 3);
        assert_eq!(deserialized.agent_edited_paths.len(), 2);
        assert_eq!(deserialized.prompt_texts.len(), 2);
        assert_eq!(deserialized.stream_start_ms, Some(1234567890));
        assert_eq!(deserialized.turn_start_ms, Some(1234567800));
        assert_eq!(deserialized.last_compaction_prompt_index, Some(2));
    }
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    #[test]
    fn credentials_debug_redacts_keys() {
        let creds = Credentials {
            api_key: Some("p70ak-FAKE-77aa88bb".into()),
            alpha_test_key: Some("p70at-FAKE-66cc55dd".into()),
            ..Credentials::default()
        };
        assert_redacted(&creds, &["p70ak-FAKE-77aa88bb", "p70at-FAKE-66cc55dd"]);
    }
}
