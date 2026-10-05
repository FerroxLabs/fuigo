use serde::{Deserialize, Deserializer};

pub fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.filter(|s| !s.is_empty()))
}

/// Deserialize `Option<Option<T>>`: absent (`None`) leaves, `null` (`Some(None)`) clears, a value sets.
/// Requires `#[serde(default, deserialize_with = "…")]`.
pub fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Ok(Some(Option::deserialize(deserializer)?))
}

// ============================================================================
// The forward-compatibility boundary
// ============================================================================
//
// Provider vocabularies are OPEN: a backend may ship a new stream-event type, content-block type
// or tool type at any moment, and modelling one as a closed Rust enum turns that release into a
// dead turn -- after the tokens are billed. Every parse of a provider-controlled discriminator
// therefore goes through this module so all three backends share ONE policy:
//
//   * a well-formed frame whose discriminating `type` tag names no modelled variant is TOLERATED
//     (skipped at the stream boundary, preserved verbatim at a nested one);
//   * a MODELLED tag whose body is malformed still FAILS CLOSED.
//
// The second rule is the whole design. "Skip what you do not recognise" must never decay into
// "ignore errors": silently dropping a corrupt `response.completed` would hang a turn instead of
// surfacing an error, and silently dropping a corrupt `tool_use` would lose a tool call with no
// diagnostic at all -- strictly worse than today's loud abort.
//
// The two are told apart by probing the TAG ALONE (`{"type": <tag>}`): a modelled tag then fails
// on a missing field, while an unmodelled one fails with serde's `unknown variant`. Probing the
// tag alone is what keeps the decision at exactly one level -- an unknown `status` nested inside a
// known `response.completed` must not be mistaken for an unknown event type.

/// True when `err` is serde's complaint that a tag names no modelled variant.
fn is_unknown_variant(err: &serde_json::Error) -> bool {
    err.to_string().contains("unknown variant")
}

/// The wire tag of `value` when `T` models no variant under that name.
///
/// Probes with the tag ALONE, so a modelled tag that fails on a missing field, and an unmodelled
/// tag nested deeper inside a modelled body, both return `None` and fail closed downstream.
/// `None` is also returned for a payload with no string `type` at all: that is not an open
/// vocabulary question, and `T`'s own parse decides it.
pub fn unknown_tag<T: serde::de::DeserializeOwned>(value: &serde_json::Value) -> Option<String> {
    let tag = value.get("type")?.as_str()?;
    match serde_json::from_value::<T>(serde_json::json!({ "type": tag })) {
        Ok(_) => None,
        Err(e) if is_unknown_variant(&e) => Some(tag.to_owned()),
        Err(_) => None,
    }
}

/// Parse one SSE `data:` payload into `T`.
///
/// `Ok(None)` means "a well-formed frame whose top-level `type` this client does not model": skip
/// it and the stream survives. `Err` means the payload is structurally broken, or carries a
/// modelled `type` with a malformed body -- both must still abort, loudly.
pub fn parse_sse_event<T: serde::de::DeserializeOwned>(
    backend: &str,
    data: &str,
) -> std::result::Result<Option<T>, serde_json::Error> {
    match serde_json::from_str::<T>(data) {
        Ok(event) => Ok(Some(event)),
        Err(first_err) => {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(data)
                && let Some(tag) = unknown_tag::<T>(&value)
            {
                tracing::warn!(
                    backend = %backend,
                    event_type = %tag,
                    "Skipping unrecognized provider stream event"
                );
                return Ok(None);
            }
            Err(first_err)
        }
    }
}

/// One value of an open provider vocabulary, for a discriminator NESTED inside a frame we model.
///
/// `Unknown` is reached only when the `type` tag names no variant of `T`; the raw JSON is kept so
/// logs and re-serialization stay faithful to the wire. A modelled tag with a malformed body still
/// fails the parse, which is what keeps this a forward-compatibility guard rather than a
/// data-loss hatch. This is the second level of the same policy `parse_sse_event` applies at the
/// top: a new `content_block` type inside a known `content_block_start` must not kill the turn,
/// while a `tool_use` block missing its `id` still must.
#[derive(Debug, Clone, PartialEq)]
pub enum Open<T> {
    Known(T),
    Unknown(serde_json::Value),
}

impl<T> Open<T> {
    /// The modelled value, or `None` for an unmodelled variant.
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// The modelled value by move, or `None` for an unmodelled variant.
    pub fn into_known(self) -> Option<T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown(_) => None,
        }
    }

    /// The verbatim wire `type` of an unmodelled variant, for logs and metrics.
    pub fn unknown_tag(&self) -> Option<&str> {
        match self {
            Self::Known(_) => None,
            Self::Unknown(value) => value.get("type").and_then(serde_json::Value::as_str),
        }
    }
}

impl<T> From<T> for Open<T> {
    fn from(value: T) -> Self {
        Self::Known(value)
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Open<T> {
    /// Tries the MODELLED parse first, and only asks the open-vocabulary question when it fails.
    ///
    /// This is a hot loop -- one `content_block_delta` per streamed token -- so the ordering is
    /// load-bearing, not stylistic. Probing the tag first cost every delta an extra
    /// `json!({"type": …})` allocation plus a throwaway enum parse *in the success case*, three
    /// passes where the closed enum it replaced did one. Trying `T` first makes the common path two
    /// (buffer to `Value`, deserialize `T` from it by reference, no clone) and moves the probe onto
    /// the failure path, where the turn is already ending.
    ///
    /// The semantics are unchanged, which is why the reorder is safe: an internally-tagged enum
    /// whose tag names no variant CANNOT parse successfully, so every input that the tag probe would
    /// have called unknown still reaches the probe here. Concretely:
    ///   * parse succeeds -> the tag was modelled and the body was well-formed -> `Known`, and the
    ///     probe could only have agreed;
    ///   * parse fails, tag unmodelled -> `Unknown`, as before;
    ///   * parse fails, tag modelled (or absent, or not a string) -> the error propagates, as
    ///     before. The fail-closed boundary this packet's design note protects is untouched.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        // Deserialize BY REFERENCE: `serde_json::from_value` takes the `Value` by value, and we
        // still need it intact to preserve an unmodelled variant verbatim.
        match T::deserialize(&value) {
            Ok(known) => Ok(Self::Known(known)),
            Err(modelled_err) => {
                if let Some(tag) = unknown_tag::<T>(&value) {
                    tracing::warn!(
                        unknown_type = %tag,
                        "Preserving an unmodelled provider variant instead of failing the parse"
                    );
                    return Ok(Self::Unknown(value));
                }
                Err(serde::de::Error::custom(modelled_err))
            }
        }
    }
}

impl<T: serde::Serialize> serde::Serialize for Open<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Known(value) => value.serialize(serializer),
            Self::Unknown(value) => value.serialize(serializer),
        }
    }
}

/// Normalize a response-side `role` string, tolerating a value this client does not model.
///
/// A chat-completions RESPONSE role is, semantically, always the assistant's; providers and
/// gateways nevertheless spell it their own way (`model`, `developer`, …) and OpenAI keeps adding
/// roles. Aborting a turn over the label on a message whose content is intact is the defect, so an
/// unmodelled role normalizes to `Assistant` and the verbatim wire string is logged, which is what
/// makes the next incident diagnosable.
///
/// Deliberately NOT applied to request-side roles: those are our own vocabulary, and an
/// unrecognized value there is our bug and must still fail.
fn role_from_wire(raw: &str) -> crate::types::Role {
    match serde_json::from_value::<crate::types::Role>(serde_json::Value::String(raw.to_owned())) {
        Ok(role) => role,
        Err(_) => {
            tracing::warn!(
                role = %raw,
                "Normalizing an unmodelled response role to `assistant`"
            );
            crate::types::Role::Assistant
        }
    }
}

/// `deserialize_with` for a required response-side `role`. See [`role_from_wire`].
pub fn response_role<'de, D>(deserializer: D) -> Result<crate::types::Role, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(role_from_wire(&String::deserialize(deserializer)?))
}

/// `deserialize_with` for an optional response-side `role`. Requires `#[serde(default)]`.
pub fn optional_response_role<'de, D>(
    deserializer: D,
) -> Result<Option<crate::types::Role>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .as_deref()
        .map(role_from_wire))
}

#[cfg(test)]
mod forward_compat_tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Frame {
        Text { text: String },
        ToolUse { id: String, input: Nested },
        Stop,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Nested {
        Json { raw: String },
    }

    /// An unmodelled tag is tolerated and the payload is kept verbatim.
    #[test]
    fn open_preserves_an_unmodelled_variant() {
        let raw = r#"{"type":"holographic_delta","payload":{"n":1},"extra":"kept"}"#;
        let open: Open<Frame> = serde_json::from_str(raw).expect("unmodelled tag must be tolerated");
        assert_eq!(open.unknown_tag(), Some("holographic_delta"));
        assert_eq!(open.known(), None);
        assert_eq!(
            serde_json::to_value(&open).expect("re-serialize"),
            serde_json::from_str::<serde_json::Value>(raw).expect("raw")
        );
    }

    /// A modelled tag still parses into the modelled variant.
    #[test]
    fn open_parses_a_modelled_variant() {
        let open: Open<Frame> =
            serde_json::from_str(r#"{"type":"text","text":"hi"}"#).expect("modelled tag");
        assert_eq!(
            open.into_known(),
            Some(Frame::Text {
                text: "hi".to_owned()
            })
        );
        // A unit variant is modelled by its tag alone and must not be mistaken for an unknown one.
        let open: Open<Frame> = serde_json::from_str(r#"{"type":"stop"}"#).expect("unit variant");
        assert_eq!(open.into_known(), Some(Frame::Stop));
    }

    /// THE line: a MODELLED tag whose body is malformed must still fail. This is what keeps
    /// "skip what you do not recognise" from decaying into "ignore errors" -- a naive
    /// `#[serde(untagged)]` catch-all silently swallows every one of these.
    #[test]
    fn open_fails_closed_on_a_corrupt_modelled_variant() {
        for raw in [
            // missing a required field
            r#"{"type":"text"}"#,
            // wrong JSON type for a required field
            r#"{"type":"text","text":42}"#,
            // missing a required nested object
            r#"{"type":"tool_use","id":"t1"}"#,
            // the NESTED discriminator is unknown -- still fatal, because the decision is made at
            // exactly one level and this level's tag (`tool_use`) IS modelled
            r#"{"type":"tool_use","id":"t1","input":{"type":"future_input"}}"#,
        ] {
            assert!(
                serde_json::from_str::<Open<Frame>>(raw).is_err(),
                "a corrupt modelled variant must not be swallowed as unknown: {raw}"
            );
        }
    }

    /// `unknown_tag` probes the tag ALONE, so it never confuses a missing field with a new variant.
    #[test]
    fn unknown_tag_isolates_the_top_level_discriminator() {
        let v = |raw: &str| serde_json::from_str::<serde_json::Value>(raw).expect("json");
        assert_eq!(
            unknown_tag::<Frame>(&v(r#"{"type":"future_frame"}"#)),
            Some("future_frame".to_owned())
        );
        // modelled tag, body missing: NOT an unknown tag
        assert_eq!(unknown_tag::<Frame>(&v(r#"{"type":"text"}"#)), None);
        // no `type` at all: not an open-vocabulary question
        assert_eq!(unknown_tag::<Frame>(&v(r#"{"text":"hi"}"#)), None);
    }

    /// `parse_sse_event` is `Ok(None)` only for an unmodelled top-level tag.
    #[test]
    fn parse_sse_event_skips_only_unmodelled_tags() {
        assert!(matches!(
            parse_sse_event::<Frame>("test", r#"{"type":"future_frame","a":1}"#),
            Ok(None)
        ));
        assert!(matches!(
            parse_sse_event::<Frame>("test", r#"{"type":"text","text":"hi"}"#),
            Ok(Some(Frame::Text { .. }))
        ));
        assert!(parse_sse_event::<Frame>("test", r#"{"type":"text"}"#).is_err());
        // not JSON at all
        assert!(parse_sse_event::<Frame>("test", "not json").is_err());
    }

    /// CANARY for the one unstable dependency the whole forward-compatibility class rests on.
    ///
    /// [`is_unknown_variant`] decides "new provider variant" vs "corrupt modelled body" by matching
    /// the substring `unknown variant` in serde_json's rendered error. That prose is not a stable
    /// API. If serde rewords it, `is_unknown_variant` returns `false` for every input, `unknown_tag`
    /// returns `None` for every input, and the entire class silently reverts to the pre-packet
    /// behaviour: every unmodelled variant kills its turn again. It fails CLOSED, so it is not a
    /// corruption risk -- but nothing would report it, and a silent revert of a shipped fix is how a
    /// regression survives a release. This test is the alarm.
    ///
    /// It pins BOTH sides of the discrimination, because drift in either one breaks it: the
    /// unknown-variant wording that must be recognized, and the missing-field wording that must NOT
    /// be mistaken for it.
    #[test]
    fn serde_error_prose_the_guard_matches_has_not_drifted() {
        let unknown_variant = serde_json::from_str::<Frame>(r#"{"type":"future_frame"}"#)
            .expect_err("an unmodelled tag must not parse");
        assert!(
            is_unknown_variant(&unknown_variant),
            "serde_json no longer renders an unmodelled enum tag as `unknown variant` -- it now \
             says {unknown_variant:?}. `is_unknown_variant` in serde_helpers.rs matches that prose, \
             so EVERY unmodelled provider variant has silently gone back to killing its turn. \
             Update the matcher (and prefer a structural test if serde has since exposed one)."
        );

        let missing_field = serde_json::from_str::<Frame>(r#"{"type":"text"}"#)
            .expect_err("a modelled tag with no body must not parse");
        assert!(
            !is_unknown_variant(&missing_field),
            "serde_json now renders a MISSING FIELD as {missing_field:?}, which \
             `is_unknown_variant` reads as an unknown variant. A corrupt modelled body would be \
              preserved as `Open::Unknown` and silently dropped instead of failing closed. This is \
              the failure direction that loses data -- fix the matcher before shipping."
        );
    }

    /// Response-side roles normalize; the request-side vocabulary is untouched.
    #[test]
    fn response_role_normalizes_unmodelled_values() {
        #[derive(Deserialize)]
        struct Msg {
            #[serde(deserialize_with = "super::response_role")]
            role: crate::types::Role,
        }
        let msg: Msg = serde_json::from_str(r#"{"role":"model"}"#).expect("unmodelled role");
        assert_eq!(msg.role, crate::types::Role::Assistant);
        let msg: Msg = serde_json::from_str(r#"{"role":"tool"}"#).expect("modelled role");
        assert_eq!(msg.role, crate::types::Role::Tool);
        // A role that is not a string at all is still malformed.
        assert!(serde_json::from_str::<Msg>(r#"{"role":7}"#).is_err());
    }
}
