//! `interject` and `queue` entries of `agentCapabilities._meta["fuigo/capabilities"]` on the ACP
//! `initialize` response (P190). A missing key means the capability is unsupported.
//!
//! One typed flag per extension a client would otherwise have to feature-detect by
//! calling it. Each flag is an object carrying at least `version`, so a flag can
//! grow without changing its type. Wire method names carry the ACP `_` prefix.
//!
//! P189 (park/quiesce) adds its `sessionPark` entry by adding a field to
//! [`InitializeFlags`] and one line to [`InitializeFlags::current`].

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct VersionedFlag {
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QueueFlag {
    pub version: u32,
    /// Wire names of the `_fuigo/queue/*` extension notifications this agent handles.
    pub methods: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InitializeFlags {
    /// `_fuigo/interject`: queue a mid-turn user interjection.
    pub interject: VersionedFlag,
    /// `_fuigo/queue/*`: edit the queued-prompt list.
    pub queue: QueueFlag,
    // P189: add `pub session_park: ...` here (wire key `sessionPark`).
}

impl InitializeFlags {
    pub fn current() -> Self {
        Self {
            interject: VersionedFlag { version: 1 },
            queue: QueueFlag {
                version: 1,
                methods: vec![
                    "_fuigo/queue/remove",
                    "_fuigo/queue/reorder",
                    "_fuigo/queue/clear",
                    "_fuigo/queue/edit",
                    "_fuigo/queue/interject",
                    "_fuigo/queue/hold_edit",
                    "_fuigo/queue/release_edit",
                ],
            },
            // P189: `session_park: ...,`
        }
    }
}

/// The entries merged into `fuigo_capabilities()`.
pub fn capability_entries() -> serde_json::Map<String, serde_json::Value> {
    match serde_json::to_value(InitializeFlags::current()) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => unreachable!("InitializeFlags is always a serializable object"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_have_the_pinned_wire_shape() {
        let v = serde_json::json!({ "capabilities": capability_entries() });
        assert_eq!(v["capabilities"]["interject"], serde_json::json!({"version": 1}));
        assert_eq!(v["capabilities"]["queue"]["version"], 1);
        let methods: Vec<&str> = v["capabilities"]["queue"]["methods"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap())
            .collect();
        assert_eq!(methods.len(), 7);
        assert!(methods.contains(&"_fuigo/queue/interject"));
        assert!(methods.iter().all(|m| m.starts_with("_fuigo/queue/")));
    }

    /// Every advertised queue method is one the parser actually handles.
    #[test]
    fn advertised_queue_methods_are_all_parsed() {
        let params = serde_json::json!({"id": "q1", "newText": "t", "orderedIds": []});
        for m in InitializeFlags::current().queue.methods {
            let internal = m.trim_start_matches('_');
            assert!(
                crate::agent::ext_parsers::parse_queue_edit_command(internal, &params, None)
                    .is_some(),
                "{m} is advertised but not parsed"
            );
        }
    }
}
