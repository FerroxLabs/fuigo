// Opt-in support for the protobuf `debug_redact` field option: messages with
// annotated fields get a redacting `Debug` derived by `veil` instead of
// prost's default, printing redacted fields as `***`. Enabled per crate by
// calling `honor_debug_redact()` on the builder.

use anyhow::Context as _;
use prost_reflect::{DescriptorPool, FieldDescriptor, OneofDescriptor};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

const DERIVE_VEIL_REDACT: &str = "#[derive(::veil::Redact)]";
const DERIVE_PLAIN_DEBUG: &str = "#[derive(Debug)]";
// Fixed-width `***` so length doesn't leak.
const REDACT_FIELD: &str = "#[redact(fixed = 3)]";
const REDACT_VARIANT: &str = "#[redact(all, fixed = 3)]";

pub(crate) fn apply(
    config: &mut prost_build::Config,
    protoc: Option<&Path>,
    protoc_include_dir: Option<&Path>,
    includes: &[&Path],
    protos: &[&Path],
) -> anyhow::Result<()> {
    let pool = compile_descriptor_pool(protoc, protoc_include_dir, includes, protos)?;

    let mut skip_debug = Vec::new();
    // Covers every message in the pool, including imports
    for msg in pool.all_messages() {
        let marked: Vec<MarkedDebugRedact> = msg.fields().filter_map(classify).collect();
        if marked.is_empty() {
            continue;
        }

        let path = msg.full_name().to_string();
        skip_debug.push(path.clone());

        // skip_debug strips Debug from the struct amd oneof enums, so
        // each needs a replacement derive: plain Debug by default, upgraded to veil for marked fields
        let mut derives = BTreeMap::from([(path.clone(), DERIVE_PLAIN_DEBUG)]);
        for oneof in msg.oneofs().filter(|o| !o.is_synthetic()) {
            derives.insert(format!("{path}.{}", oneof.name()), DERIVE_PLAIN_DEBUG);
        }
        for marked_field in marked {
            let (owning_type_path, field_path, field_redact_attr) = match marked_field {
                MarkedDebugRedact::Plain(field) => (
                    path.clone(),
                    format!("{path}.{}", field.name()),
                    REDACT_FIELD,
                ),
                MarkedDebugRedact::OneofMember(field, oneof) => (
                    format!("{path}.{}", oneof.name()),
                    format!("{path}.{}.{}", oneof.name(), field.name()),
                    REDACT_VARIANT,
                ),
            };
            config.field_attribute(field_path, field_redact_attr);
            derives.insert(owning_type_path, DERIVE_VEIL_REDACT);
        }
        for (type_path, derive_attr) in derives {
            config.type_attribute(type_path, derive_attr);
        }
    }
    // skip_debug replaces rather than appends — set once.
    config.skip_debug(skip_debug);
    Ok(())
}

/// Returns the full name of the first field marked `debug_redact = true` in
/// the crate's own protos (imports are their owners' responsibility), if any.
pub(crate) fn first_marked_field(
    protoc: Option<&Path>,
    protoc_include_dir: Option<&Path>,
    includes: &[&Path],
    protos: &[&Path],
) -> anyhow::Result<Option<String>> {
    let pool = compile_descriptor_pool(protoc, protoc_include_dir, includes, protos)?;
    Ok(first_marked_field_in_pool(&pool, protos))
}

/// The half of [`first_marked_field`] that runs once `protoc` has produced a pool.
/// Split out so tests can drive it from a recorded descriptor set instead of protoc.
fn first_marked_field_in_pool(pool: &DescriptorPool, protos: &[&Path]) -> Option<String> {
    // Normalize to `/` — descriptor file names always use it, filesystem paths may not.
    let compiled: Vec<String> = protos
        .iter()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .collect();

    pool.all_messages()
        .filter(|m| is_compiled_here(&compiled, m.parent_file().name()))
        .flat_map(|m| m.fields().collect::<Vec<_>>())
        .find(|f| classify(f.clone()).is_some())
        .map(|f| f.full_name().to_string())
}

fn is_compiled_here(compiled: &[String], file_name: &str) -> bool {
    fn is_path_suffix(longer: &str, suffix: &str) -> bool {
        longer
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.is_empty() || rest.ends_with('/'))
    }
    compiled
        .iter()
        .any(|p| is_path_suffix(p, file_name) || is_path_suffix(file_name, p))
}

fn compile_descriptor_pool(
    protoc: Option<&Path>,
    protoc_include_dir: Option<&Path>,
    includes: &[&Path],
    protos: &[&Path],
) -> anyhow::Result<DescriptorPool> {
    let tmp = tempfile::TempDir::new()?;
    let fds_path = tmp.path().join("debug-redact.pbbin");

    let mut command = Command::new(protoc.unwrap_or(Path::new("protoc")));
    command
        .arg(format!("--descriptor_set_out={}", fds_path.display()))
        .arg("--include_imports")
        .arg("--experimental_allow_proto3_optional");
    if let Some(dir) = protoc_include_dir {
        command.arg(format!("-I{}", dir.display()));
    }
    for include in includes {
        command.arg(format!("-I{}", include.display()));
    }
    for proto in protos {
        command.arg(proto);
    }
    let status = command
        .status()
        .context("debug_redact: failed to run protoc")?;
    anyhow::ensure!(status.success(), "debug_redact: protoc failed");

    let bytes = std::fs::read(&fds_path)?;
    decode_descriptor_pool(&bytes)
}

fn decode_descriptor_pool(bytes: &[u8]) -> anyhow::Result<DescriptorPool> {
    // Must decode with prost-reflect directly: a round-trip through
    // prost_types drops extension options as unknown fields.
    DescriptorPool::decode(bytes).context("debug_redact: decode descriptor set")
}

enum MarkedDebugRedact {
    Plain(FieldDescriptor),
    // OneOf fields requires special handling due to intermediate structs generated https://github.com/tokio-rs/prost#oneof-fields
    OneofMember(FieldDescriptor, OneofDescriptor),
}

fn classify(field: FieldDescriptor) -> Option<MarkedDebugRedact> {
    let marked = field
        .options()
        .get_field_by_name("debug_redact")
        .map(|v| v.as_bool().unwrap_or(false))
        .unwrap_or(false);
    if !marked {
        return None;
    }
    Some(
        // Excludes synthetic oneofs (e.g. optional): those generate plain struct fields, not enum variants.
        match field.containing_oneof().filter(|o| !o.is_synthetic()) {
            Some(oneof) => MarkedDebugRedact::OneofMember(field, oneof),
            None => MarkedDebugRedact::Plain(field),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // These fixtures are descriptor sets recorded from the pinned `bin/protoc`
    // (libprotoc 29.3) rather than compiled by a `protoc` found at test time.
    // `debug_redact` is a `FieldOptions` field that only exists in protobuf >= 23, and
    // `find_protoc` deliberately falls back to whatever `protoc` is on `PATH` when the
    // pinned dotslash wrapper cannot run (no `dotslash`, or no network to fetch it).
    // On the offline CI image that fallback is libprotoc 3.21.12, which rejects the
    // option outright — so compiling the fixtures here tested the ambient toolchain,
    // not this module. Decoding recorded bytes keeps the test hermetic while still
    // exercising real protoc output.
    //
    // Regenerate after editing either .proto, from this crate's directory:
    //   for p in debug_redact_test debug_redact_plain; do \
    //     ../../../bin/protoc --descriptor_set_out=test_data/$p.pbbin --include_imports \
    //       --experimental_allow_proto3_optional -Itest_data $p.proto; done
    const TEST_FDS: &[u8] = include_bytes!("../test_data/debug_redact_test.pbbin");
    const PLAIN_FDS: &[u8] = include_bytes!("../test_data/debug_redact_plain.pbbin");

    fn field(name: &str) -> FieldDescriptor {
        let pool = decode_descriptor_pool(TEST_FDS).unwrap();
        pool.get_message_by_name("t.M")
            .unwrap()
            .get_field_by_name(name)
            .unwrap()
    }

    #[test]
    fn classifies_marked_fields_by_oneof_membership() {
        assert!(classify(field("plain")).is_none());
        assert!(matches!(
            classify(field("marked")),
            Some(MarkedDebugRedact::Plain(_))
        ));
        assert!(matches!(
            classify(field("opt_marked")),
            Some(MarkedDebugRedact::Plain(_))
        ));
        assert!(matches!(
            classify(field("oneof_marked")),
            Some(MarkedDebugRedact::OneofMember(..))
        ));
        assert!(classify(field("oneof_plain")).is_none());
        assert!(classify(field("other_plain")).is_none());
    }

    #[test]
    fn first_marked_field_finds_annotations_and_ignores_comments() {
        let find = |fds: &[u8], protos: &[&Path]| {
            first_marked_field_in_pool(&decode_descriptor_pool(fds).unwrap(), protos)
        };

        // Marked fields in directly compiled protos are found.
        assert_eq!(
            find(TEST_FDS, &[Path::new("debug_redact_test.proto")]).as_deref(),
            Some("t.M.marked")
        );
        // A proto that only mentions the option in comments reports nothing.
        assert_eq!(
            find(PLAIN_FDS, &[Path::new("debug_redact_plain.proto")]),
            None
        );
    }
}
