//! OpenCode `write` tool — writes entire file contents to disk.
//!
//! Creates parent directories as needed and emits `FileWritten` notifications.

use crate::notification::types::FileWritten;

use crate::types::output::{
    SearchReplaceEditContextInformation, SearchReplaceEditDetail, SearchReplaceEditsApplied,
    SearchReplaceOutput,
};
use crate::types::requirements::Expr;
#[allow(unused_imports)]
use crate::types::resources::{
    Cwd, DisplayCwd, FileSystem, NotificationHandle, SharedResources, resolve_model_path,
};
use crate::types::tool::{ToolKind, ToolNamespace};

// ─── Description ─────────────────────────────────────────────────────

const DESCRIPTION: &str = r#"Create or overwrite a file.

- Writing to an existing path replaces the file${%- if tools.by_kind.read %} — read it first with the ${{ tools.by_kind.read }} tool${%- endif %}.
- Parent directories are created for you."#;

// ─── Input ───────────────────────────────────────────────────────────

/// Input for the `write` tool.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WriteInput {
    /// The absolute path to the file to write.
    pub file_path: String,

    /// The full file content to write.
    pub content: String,
}

// ─── Tool ────────────────────────────────────────────────────────────

/// OpenCode write tool — writes entire file contents to disk.
#[derive(Debug, Default)]
pub struct WriteTool;

type WriteOutput = SearchReplaceOutput;

impl crate::types::tool_metadata::ToolMetadata for WriteTool {
    fn lock_path_param(&self) -> Option<&'static str> {
        Some("file_path")
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Write
    }

    fn tool_namespace(&self) -> ToolNamespace {
        ToolNamespace::OpenCode
    }

    fn description_template(&self) -> &str {
        DESCRIPTION
    }

    fn emitted_notifications(&self) -> &'static [&'static str] {
        &["FileWritten"]
    }

    fn requires_expr(&self) -> Expr<crate::types::requirements::ToolRequirement> {
        Expr::True
    }
}

impl fuigo_tool_runtime::Tool for WriteTool {
    type Args = WriteInput;
    type Output = WriteOutput;

    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new("write").expect("valid tool id")
    }

    fn description(
        &self,
        _ctx: &::fuigo_tool_runtime::ListToolsContext,
    ) -> fuigo_tool_types::ToolDescription {
        fuigo_tool_types::ToolDescription::new(
            "write",
            crate::types::tool_metadata::ToolMetadata::sanitized_description_template(self),
        )
    }

    fn capabilities(&self) -> fuigo_tool_protocol::ToolCapabilities {
        fuigo_tool_protocol::ToolCapabilities {
            is_read_only: false,
            tool_scope: Some(fuigo_tool_protocol::ToolScope::Write),
            ..Default::default()
        }
    }

    #[tracing::instrument(name = "tool.write", skip_all)]
    #[allow(clippy::disallowed_methods, reason = "file tool write of a model/user-chosen path (user content); not inside a session folder")]
    async fn run(
        &self,
        ctx: fuigo_tool_runtime::ToolCallContext,
        input: WriteInput,
    ) -> Result<WriteOutput, fuigo_tool_runtime::ToolError> {
        use crate::types::tool_metadata::shared_resources;
        let resources = shared_resources(&ctx)?;

        let (cwd, display_cwd, fs, notification_handle) = {
            let cwd = crate::types::tool_metadata::resolve_cwd(&ctx, &resources).await?;
            let res = resources.lock().await;
            let display_cwd = res.get::<DisplayCwd>().map(|d| d.0.clone());
            let fs = res.require::<FileSystem>()?.0.clone();
            let notification_handle = res.require::<NotificationHandle>()?.0.clone();
            (cwd, display_cwd, fs, notification_handle)
        };
        let tool_call_id = ctx.call_id.as_str().to_owned();

        // Resolve the model-provided path.
        let path = resolve_model_path(&cwd, display_cwd.as_deref(), &input.file_path);
        // Serialised with `apply_patch` on the same file (audit S4-F9).
        let _edit_lock = crate::util::lock_path::lock_edit_paths(&[&path], &cwd).await;

        // P166 Grok r5 MEDIUM 3 sweep: like the edit tools, refuse a gitignored path (logical or physical) before reading
        // the old content or writing.
        if crate::implementations::fuigo_build::read_file::tool_path_refused_by_gitignore(
            &resources, &path, true,
        )
        .await
        {
            return Ok(SearchReplaceOutput::InvalidInput(format!(
                "Error: {} is ignored by .gitignore and cannot be edited.",
                input.file_path
            )));
        }

        // ── Check if file exists and read old content ────────────
        // Only NotFound means "did not exist"; non-UTF-8 or unreadable content is reported without a snapshot so a
        // rewind never deletes the file or writes lossy text back (audit S4-F3).
        let read =
            crate::implementations::fuigo_build::read_file::read_tool_source(fs.as_ref(), &path).await;
        // A file over the source cap is overwritten all the same, but its old content cannot be held for a rewind: warn
        // instead of refusing (review L16; the read was the only reason for the refusal).
        let over_cap = read.as_ref().err().and_then(|e| {
            crate::implementations::fuigo_build::read_file::source_too_large_message(e, &input.file_path, "write")
        });
        if over_cap.is_some() {
            tracing::warn!(path = %path.display(), "write: overwriting a file larger than 256 MB; no rewind snapshot is kept");
        }
        let prior = crate::notification::types::PriorContent::from_read(read);
        let existed = prior.existed();
        let old_content = prior.previous_content();

        // ── Create parent directories if needed ──────────────────
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                let ce = crate::computer::types::ComputerError::from(e);
                fuigo_tool_runtime::ToolError::execution(
                    fuigo_tool_protocol::ToolId::new("write").expect("valid"),
                    ce.to_string(),
                )
            })?;
        }

        // ── Write the file ───────────────────────────────────────
        fs.write_file(&path, input.content.as_bytes())
            .await
            .map_err(|e| {
                fuigo_tool_runtime::ToolError::execution(
                    fuigo_tool_protocol::ToolId::new("write").expect("valid"),
                    e.to_string(),
                )
            })?;

        // ── Send FileWritten notification ────────────────────────
        notification_handle.send_file_written(FileWritten {
            tool_call_id,
            absolute_path: path.clone(),
            content: input.content.clone(),
            previous_content: old_content.clone(),
            is_new_file: prior.is_new_file(),
        });

        let old_string = old_content.unwrap_or_default();
        let new_string = input.content;

        let edits = vec![SearchReplaceEditDetail {
            old_string: old_string.clone(),
            old_line: 1,
            new_string: new_string.clone(),
            new_line: 1,
            context_before: String::new(),
            context_after: String::new(),
            line_prefix: String::new(),
        }];

        let mut tool_output_for_prompt = if existed {
            format!("Wrote file successfully to {}.", path.display())
        } else {
            format!("The file {} has been created.", path.display())
        };
        if over_cap.is_some() {
            tool_output_for_prompt.push_str(
                " Warning: the file it replaced was larger than 256 MB, so no snapshot of it was kept and a rewind \
                 cannot restore it.",
            );
        }

        // Counter span: lines written (diffed against prior content so an
        // overwrite only counts the lines that actually changed).
        let (lines_added, lines_removed) =
            crate::types::output::line_diff(&old_string, &new_string);
        tracing::info_span!(
            "edit.lines",
            tool_name = "write",
            lines_added = lines_added,
            lines_removed = lines_removed
        )
        .in_scope(|| {});

        Ok(SearchReplaceOutput::EditsApplied(
            SearchReplaceEditsApplied {
                old_string,
                new_string,
                tool_output_for_prompt: tool_output_for_prompt.clone(),
                tool_output_for_prompt_concise: Some(tool_output_for_prompt),
                absolute_path: path,
                edits: SearchReplaceEditContextInformation { details: edits },
                patch: None,
                unicode_normalized: false,
            },
        ))
    }
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    use crate::types::tool_metadata::test_ctx;
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::*;
    use crate::computer::local::LocalFs;
    use crate::notification::types::ToolNotificationHandle;
    use crate::types::resources::Resources;
    use tempfile::TempDir;

    /// Set up Resources with real filesystem for tests.
    fn test_resources(cwd: &std::path::Path) -> Resources {
        let mut resources = Resources::new();
        resources.insert(Cwd(cwd.to_path_buf()));
        resources.insert(FileSystem(Arc::new(LocalFs)));
        resources.insert(NotificationHandle(ToolNotificationHandle::noop()));
        resources
    }

    // ── Write new file ──────────────────────────────────────────

    /// Review L16 (was audit S4-F7's refusal): a file over the source cap cannot be pre-read for a rewind snapshot, but
    /// the write is not refused; the model is told the overwrite has no snapshot.
    #[tokio::test]
    async fn write_overwrites_a_file_over_the_source_cap_with_a_warning() {
        let tmp = TempDir::new().unwrap();
        let big = tmp.path().join("big.log");
        let len = (crate::implementations::fuigo_build::read_file::MAX_READ_SOURCE_BYTES + 1) as u64;
        std::fs::File::create(&big).unwrap().set_len(len).unwrap();
        let resources = test_resources(tmp.path());
        let input = WriteInput {
            file_path: big.to_string_lossy().into_owned(),
            content: "x".to_string(),
        };
        let result = fuigo_tool_runtime::Tool::run(&WriteTool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();
        match result {
            SearchReplaceOutput::EditsApplied(applied) => {
                assert!(applied.tool_output_for_prompt.contains("256 MB"), "{}", applied.tool_output_for_prompt);
                assert!(applied.tool_output_for_prompt.contains("rewind"), "{}", applied.tool_output_for_prompt);
            }
            other => panic!("expected the write to go ahead, got {other:?}"),
        }
        assert_eq!(std::fs::read(&big).unwrap(), b"x");
    }

    #[tokio::test]
    async fn write_new_file_creates_with_correct_content() {
        let tmp = TempDir::new().unwrap();
        let tool = WriteTool;
        let resources = test_resources(tmp.path());
        let shared_resources = resources.into_shared();

        let input = WriteInput {
            file_path: tmp.path().join("new.txt").to_string_lossy().into_owned(),
            content: "hello\nworld\n".to_string(),
        };
        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared_resources.clone()), input)
            .await
            .unwrap();

        match &result {
            SearchReplaceOutput::EditsApplied(applied) => {
                assert!(applied.tool_output_for_prompt.contains("created"));
            }
            other => panic!("Expected EditsApplied, got {:?}", other),
        }
        let content = std::fs::read_to_string(tmp.path().join("new.txt")).unwrap();
        assert_eq!(content, "hello\nworld\n");
    }

    // ── Overwrite existing file ─────────────────────────────────

    #[tokio::test]
    async fn overwrite_existing_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("existing.txt");
        std::fs::write(&file_path, "old content\n").unwrap();

        let tool = WriteTool;
        let resources = test_resources(tmp.path());

        let input = WriteInput {
            file_path: file_path.to_string_lossy().into_owned(),
            content: "new content\n".to_string(),
        };
        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();

        match &result {
            SearchReplaceOutput::EditsApplied(applied) => {
                assert!(applied.tool_output_for_prompt.contains("successfully"));
            }
            other => panic!("Expected EditsApplied, got {:?}", other),
        }
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "new content\n");
    }

    // ── Creates parent directories ──────────────────────────────

    #[tokio::test]
    async fn creates_parent_directories() {
        let tmp = TempDir::new().unwrap();
        let tool = WriteTool;
        let resources = test_resources(tmp.path());

        let nested = tmp.path().join("a/b/c/file.txt");
        let input = WriteInput {
            file_path: nested.to_string_lossy().into_owned(),
            content: "nested\n".to_string(),
        };
        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();

        assert!(matches!(result, SearchReplaceOutput::EditsApplied(_)));
        let content = std::fs::read_to_string(&nested).unwrap();
        assert_eq!(content, "nested\n");
    }

    // ── Tool metadata ──────────────────────────────────────────

    #[test]
    fn tool_metadata() {
        use crate::types::tool_metadata::ToolMetadata;
        let tool = WriteTool;
        assert_eq!(fuigo_tool_runtime::Tool::id(&tool).as_str(), "write");
        assert!(matches!(tool.kind(), ToolKind::Write));
        assert!(matches!(tool.tool_namespace(), ToolNamespace::OpenCode));
    }

    // ── Serde roundtrip ────────────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let json = r#"{"file_path":"/tmp/test.txt","content":"hello world"}"#;
        let input: WriteInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.file_path, "/tmp/test.txt");
        assert_eq!(input.content, "hello world");

        // Serializes back to snake_case
        let serialized = serde_json::to_string(&input).unwrap();
        assert!(serialized.contains("file_path"));
        assert!(!serialized.contains("filePath"));
    }

    // ── Empty content write ────────────────────────────────────

    #[tokio::test]
    async fn empty_content_write() {
        let tmp = TempDir::new().unwrap();
        let tool = WriteTool;
        let resources = test_resources(tmp.path());

        let file_path = tmp.path().join("empty.txt");
        let input = WriteInput {
            file_path: file_path.to_string_lossy().into_owned(),
            content: String::new(),
        };
        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();

        assert!(matches!(result, SearchReplaceOutput::EditsApplied(_)));
        assert!(file_path.exists());
        let content = std::fs::read_to_string(&file_path).unwrap();
        assert!(content.is_empty());
    }

    // ── Overwrite preserves path in output ─────────────────────

    #[tokio::test]
    async fn overwrite_preserves_path_in_output() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("output_check.txt");
        std::fs::write(&file_path, "old\n").unwrap();

        let tool = WriteTool;
        let resources = test_resources(tmp.path());

        let input = WriteInput {
            file_path: file_path.to_string_lossy().into_owned(),
            content: "new\n".to_string(),
        };
        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();

        match &result {
            SearchReplaceOutput::EditsApplied(applied) => {
                assert!(
                    applied
                        .tool_output_for_prompt
                        .contains(&file_path.display().to_string()),
                    "tool_output_for_prompt should contain the file path: {}",
                    applied.tool_output_for_prompt
                );
                assert_eq!(applied.absolute_path, file_path);
            }
            other => panic!("Expected EditsApplied, got {:?}", other),
        }
    }

    // ── Relative path resolution ───────────────────────────────

    #[tokio::test]
    async fn relative_path_resolution() {
        let tmp = TempDir::new().unwrap();
        let tool = WriteTool;
        let resources = test_resources(tmp.path());

        let input = WriteInput {
            file_path: "subdir/relative.txt".to_string(),
            content: "resolved\n".to_string(),
        };
        let result = fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();

        let expected = tmp.path().join("subdir/relative.txt");
        match &result {
            SearchReplaceOutput::EditsApplied(applied) => {
                assert_eq!(applied.absolute_path, expected);
            }
            other => panic!("Expected EditsApplied, got {:?}", other),
        }
        let content = std::fs::read_to_string(&expected).unwrap();
        assert_eq!(content, "resolved\n");
    }

    // ── Missing FileSystem resource ────────────────────────────

    #[tokio::test]
    async fn missing_filesystem_resource() {
        let mut resources = Resources::new();
        resources.insert(Cwd(PathBuf::from("/tmp")));
        resources.insert(NotificationHandle(ToolNotificationHandle::noop()));
        // No FileSystem inserted

        let tool = WriteTool;
        let input = WriteInput {
            file_path: "/tmp/test.txt".to_string(),
            content: "data".to_string(),
        };
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing required resource"),
        );
    }

    // ── Missing Cwd resource ───────────────────────────────────

    #[tokio::test]
    async fn missing_cwd_resource() {
        let mut resources = Resources::new();
        resources.insert(FileSystem(Arc::new(LocalFs)));
        resources.insert(NotificationHandle(ToolNotificationHandle::noop()));
        // No Cwd inserted

        let tool = WriteTool;
        let input = WriteInput {
            file_path: "/tmp/test.txt".to_string(),
            content: "data".to_string(),
        };
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(resources.into_shared()), input).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Cwd not available"),
        );
    }

    // ── Notification fields ───────────────────────────────────

    #[test]
    fn notification_fields() {
        // Notification verification requires capturing handle.
        // Covered at integration layer.
    }

    /// P166 Grok r5 MEDIUM 3 sweep: the OpenCode write reads the old content (for the diff) and overwrites it; like the
    /// other edit tools it refuses a gitignored path, logical or physical.
    #[cfg(unix)]
    #[tokio::test]
    async fn opencode_write_refuses_ignored_logical_path_behind_symlink() {
        let repo = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("key.txt"), "TOP SECRET\n").unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.path().join("secret")).unwrap();
        let canonical = dunce::canonicalize(repo.path()).unwrap();
        let mut builder = ignore::gitignore::GitignoreBuilder::new(&canonical);
        builder.add_line(None, "secret/").unwrap();
        let mut resources = test_resources(repo.path());
        resources.insert(crate::types::resources::GitignoreFilter::new(builder.build().unwrap(), canonical));
        let result = fuigo_tool_runtime::Tool::run(
            &WriteTool,
            test_ctx(resources.into_shared()),
            WriteInput {
                file_path: "secret/key.txt".to_owned(),
                content: "x".to_owned(),
            },
        )
        .await
        .unwrap();
        match result {
            SearchReplaceOutput::InvalidInput(msg) => assert!(msg.contains("ignored by .gitignore"), "{msg}"),
            other => panic!("expected the gitignore refusal, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(outside.path().join("key.txt")).unwrap(), "TOP SECRET\n");
    }

    #[tokio::test]
    async fn overwrite_of_non_utf8_file_is_not_reported_as_new_or_lossy() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("l.txt"), b"a\xff\n").unwrap();
        let (handle, mut rx) = ToolNotificationHandle::channel();
        let mut resources = test_resources(tmp.path());
        resources.insert(NotificationHandle(handle));
        let input = WriteInput {
            file_path: tmp.path().join("l.txt").to_string_lossy().into_owned(),
            content: "new\n".to_string(),
        };
        fuigo_tool_runtime::Tool::run(&WriteTool, test_ctx(resources.into_shared()), input)
            .await
            .unwrap();
        let mut seen = 0;
        while let Ok(n) = rx.try_recv() {
            if let crate::notification::types::ToolNotification::FileWritten(w) = n {
                seen += 1;
                assert_eq!(w.previous_content, None);
                assert!(!w.is_new_file);
            }
        }
        assert_eq!(seen, 1);
    }
}
