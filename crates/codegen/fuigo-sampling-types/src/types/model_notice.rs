//! A short per-model message, such as a deprecation warning, that clients show while the model is selected.
//!
//! The shell reads it from `[model.<id>] notice` in the user's or admin's config (a plain string or a
//! `{ severity, text, label }` table). Clients receive it as ACP `ModelInfo._meta.notice`.
//! The text is config text shown in a terminal: `fuigo-shell` scrubs it when it parses the config and when it
//! builds the ACP meta, and the pager scrubs it again when it paints.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The model `meta` key that carries a [`ModelNotice`].
pub const MODEL_NOTICE_META_KEY: &str = "notice";

/// Longest notice text kept, in characters.
pub const MODEL_NOTICE_MAX_TEXT_CHARS: usize = 160;

/// Longest notice label kept, in characters.
const MODEL_NOTICE_MAX_LABEL_CHARS: usize = 24;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelNoticeSeverity {
    Warning,
    Critical,
    /// Also the fallback for a severity this build does not know.
    #[default]
    #[serde(other)]
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelNotice {
    pub severity: ModelNoticeSeverity,
    pub text: String,
    /// Short badge text, such as `deprecated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Wire shape: a bare string is an info notice, a table carries severity and label.
#[derive(Deserialize)]
#[serde(untagged)]
enum NoticeWire {
    Text(String),
    Full {
        #[serde(default)]
        severity: ModelNoticeSeverity,
        text: String,
        #[serde(default)]
        label: Option<String>,
    },
}

impl<'de> Deserialize<'de> for ModelNotice {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match NoticeWire::deserialize(deserializer)? {
            NoticeWire::Text(text) => ModelNotice {
                severity: ModelNoticeSeverity::Info,
                text,
                label: None,
            },
            NoticeWire::Full {
                severity,
                text,
                label,
            } => ModelNotice {
                severity,
                text,
                label,
            },
        })
    }
}

impl ModelNotice {
    /// Trims and caps both strings. Returns `None` when the text is blank.
    #[must_use]
    pub fn normalized(self) -> Option<Self> {
        let text = cap_chars(self.text.trim(), MODEL_NOTICE_MAX_TEXT_CHARS);
        if text.is_empty() {
            return None;
        }
        let label = self
            .label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(|label| cap_chars(label, MODEL_NOTICE_MAX_LABEL_CHARS));
        Some(ModelNotice {
            severity: self.severity,
            text,
            label,
        })
    }

    /// Reads a notice from JSON. A malformed value is dropped with a warning.
    pub fn from_value(value: &Value) -> Option<Self> {
        match ModelNotice::deserialize(value) {
            Ok(notice) => notice.normalized(),
            Err(err) => {
                tracing::warn!(value = %value, error = %err, "model notice: ignoring malformed value");
                None
            }
        }
    }

    pub fn to_meta_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Returns the notice in a model's ACP `meta`, or `None` when there is none or it is malformed.
/// It drops a malformed notice without a log line. The TUI calls it on every frame.
pub fn parse_model_notice_meta(
    meta: Option<&serde_json::Map<String, Value>>,
) -> Option<ModelNotice> {
    ModelNotice::deserialize(meta?.get(MODEL_NOTICE_META_KEY)?)
        .ok()?
        .normalized()
}

/// Cuts `s` to `max_chars` characters, the last one an ellipsis when anything was cut.
fn cap_chars(s: &str, max_chars: usize) -> String {
    if s.chars().nth(max_chars).is_none() {
        return s.to_owned();
    }
    let kept: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{}…", kept.trim_end())
}

#[cfg(test)]
#[path = "model_notice_tests.rs"]
mod tests;
