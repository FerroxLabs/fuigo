#![no_main]
//! Several JSON objects in one tool call: `try_extract_concatenated_json_objects` and `select_concatenated_object`.
//! The product file is compiled in by path (the fuigo-shell crate itself is far too large to build per fuzz run).

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/codegen/fuigo-shell/src/session/helpers/tool_input_parsing.rs"]
#[allow(dead_code)]
mod tool_input_parsing;
use tool_input_parsing::*;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = normalize_empty_arguments(s);
    let Some(objects) = try_extract_concatenated_json_objects(s) else {
        return;
    };
    // At least two, and every one an object.
    assert!(objects.len() >= 2);
    assert!(objects.iter().all(|o| o.is_object()));
    // The input itself must not be one valid JSON document (those are never split) and must start with `{`.
    let trimmed = s.trim();
    assert!(trimmed.starts_with('{'));
    assert!(serde_json::from_str::<serde_json::Value>(trimmed).is_err());
    // Selection is total and in range, whatever the first match claims.
    for first in [None, Some(0), Some(objects.len() - 1), Some(objects.len()), Some(usize::MAX)] {
        let (index, value) = select_concatenated_object(&objects, first);
        assert!(index < objects.len());
        assert_eq!(value, objects[index]);
    }
    // serde_json gives its private raw-value key a meaning of its own, so a value holding it does not print and parse
    // back as the same value; that is the library's, not the splitter's.
    if s.contains("$serde_json") {
        return;
    }
    // Round trip: re-serialising the objects back to back yields the same objects.
    let joined: String = objects.iter().map(|o| o.to_string()).collect();
    let again = try_extract_concatenated_json_objects(&joined).expect("a joined run of objects splits again");
    assert!(same_shape(&json_array(again), &json_array(objects.clone())));
});

fn json_array(v: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::Value::Array(v)
}

/// Equal, except that two numbers always agree: without serde_json's `float_roundtrip` a large float does not survive
/// print and parse bit for bit, which says nothing about where the splitter cuts.
fn same_shape(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    use serde_json::Value::*;
    match (a, b) {
        (Number(_), Number(_)) => true,
        (Array(x), Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same_shape(p, q)),
        (Object(x), Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, p)| y.get(k).is_some_and(|q| same_shape(p, q)))
        }
        _ => a == b,
    }
}
