//! `ApplyPatchTool` — Tool trait implementation for the codex apply-patch format.
//!
//! Wires the pure-library patch engine (parser + apply) through `AsyncFileSystem`
//! for all I/O and emits `FileWritten` notifications.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use crate::computer::types::AsyncFileSystem;
use crate::implementations::fuigo_build::read_file::read_tool_source;
use crate::notification::types::{FileWritten, PriorContent};

use crate::types::output::{ApplyPatchFileResult, ApplyPatchOutput};
use crate::types::requirements::Expr;
#[allow(unused_imports)]
use crate::types::resources::{Cwd, FileSystem, NotificationHandle, SharedResources};
use crate::types::tool::{ToolKind, ToolNamespace};

use super::errors::ParseError;
use super::parser::{self, Hunk};
use super::{apply, errors::ApplyPatchError};

// ─── Description ─────────────────────────────────────────────────────

/// Tool description derived from the codex `apply_patch_tool_instructions.md`.
const DESCRIPTION: &str = r#"Use this tool to edit files.
Your patch language is a stripped‑down, file‑oriented diff format designed to be easy to parse and safe to apply. You can think of it as a high‑level envelope:

*** Begin Patch
[ one or more file sections ]
*** End Patch

Within that envelope, you get a sequence of file operations.
You MUST include a header to specify the action you are taking.
Each operation starts with one of three headers:

*** Add File: <path> - create a new file. Every following line is a + line (the initial contents).
*** Delete File: <path> - remove an existing file. No hunks follow this header.
*** Update File: <path> - patch an existing file in place (optionally with a rename).

May be immediately followed by *** Move to: <new path> if you want to rename the file.
Then one or more “hunks”, each introduced by @@ (optionally followed by a hunk header).
Within a hunk each line starts with:
+ for inserted text,
- for removed text, or
  (a space) for unchanged context.

For instructions on [context_before] and [context_after]:
- By default, show 3 lines of code immediately above and 3 lines immediately below each change. If a change is within 3 lines of a previous change, do NOT duplicate the first change’s [context_after] lines in the second change’s [context_before] lines.
- If 3 lines of context is insufficient to uniquely identify the snippet of code within the file, use the @@ operator to indicate the class or function to which the snippet belongs. For instance, we might have:
@@ class BaseClass
[3 lines of pre-context]
- [old_code]
+ [new_code]
[3 lines of post-context]

- If a code block is repeated so many times in a class or function such that even a single `@@` statement and 3 lines of context cannot uniquely identify the snippet of code, you can use multiple `@@` statements to jump to the right context. For instance:

@@ class BaseClass
@@ 	 def method():
[3 lines of pre-context]
- [old_code]
+ [new_code]
[3 lines of post-context]

The full grammar definition is below:
Patch := Begin { FileOp } End
Begin := "*** Begin Patch" NEWLINE
End := "*** End Patch" NEWLINE
FileOp := AddFile | DeleteFile | UpdateFile
AddFile := "*** Add File: " path NEWLINE { "+" line NEWLINE }
DeleteFile := "*** Delete File: " path NEWLINE
UpdateFile := "*** Update File: " path NEWLINE [ MoveTo ] { Hunk }
MoveTo := "*** Move to: " newPath NEWLINE
Hunk := "@@" [ header ] NEWLINE { HunkLine } [ "*** End of File" NEWLINE ]
HunkLine := (" " | "-" | "+") text NEWLINE

A full patch can combine several operations:

*** Begin Patch
*** Add File: hello.txt
+Hello world
*** Update File: src/app.py
*** Move to: src/main.py
@@ def greet():
-print("Hi")
+print("Hello, world!")
*** Delete File: obsolete.txt
*** End Patch

It is important to remember:

- Every patch MUST start with *** Begin Patch and end with *** End Patch, including delete-only patches
- You must include a header with your intended action (Add/Delete/Update)
- You must prefix new lines with `+` even when creating a new file
"#;

// ─── Input ───────────────────────────────────────────────────────────

/// Input for the `apply_patch` tool.
///
/// Deserializes from the JSON function form `{"patch": "..."}` and from the freeform form: a bare string, or the
/// `{"raw": "..."}` / `{"input": "..."}` envelope the shell wraps non-JSON tool arguments in when the Responses
/// backend advertises this tool as a `custom` (grammar-constrained) tool.
#[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
pub struct ApplyPatchInput {
    /// The patch text in codex patch format.
    pub patch: String,
}

impl<'de> serde::Deserialize<'de> for ApplyPatchInput {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Text(String),
            Object {
                #[serde(alias = "raw", alias = "input")]
                patch: String,
            },
        }
        Ok(match Wire::deserialize(deserializer)? {
            Wire::Text(patch) | Wire::Object { patch } => Self { patch },
        })
    }
}

// ─── Freeform (Responses `custom` tool) form ─────────────────────────

/// Description of the freeform form, Codex's wording (`codex-rs/core/src/tools/handlers/apply_patch_spec.rs`, rust-v0.154.0).
pub const APPLY_PATCH_FREEFORM_DESCRIPTION: &str = "The `apply_patch` tool can be used to edit files. This is a FREEFORM tool, so do not wrap the patch in JSON.";

/// Codex's Lark grammar for the freeform form, verbatim (`codex-rs/core/assets/tools/apply_patch.lark`, rust-v0.154.0).
pub const APPLY_PATCH_LARK_GRAMMAR: &str = r#"start: begin_patch hunk+ end_patch
begin_patch: "*** Begin Patch" LF
end_patch: "*** End Patch" LF?

hunk: add_hunk | delete_hunk | update_hunk
add_hunk: "*** Add File: " filename LF add_line+
delete_hunk: "*** Delete File: " filename LF
update_hunk: "*** Update File: " filename LF change_move? change?

filename: /(.+)/
add_line: "+" /(.*)/ LF -> line

change_move: "*** Move to: " filename LF
change: (change_context | change_line)+ eof_line?
change_context: ("@@" | "@@ " /(.+)/) LF
change_line: ("+" | "-" | " ") /(.*)/ LF
eof_line: "*** End of File" LF

%import common.LF
"#;

// ─── Tool ────────────────────────────────────────────────────────────

/// ApplyPatch tool — applies multi-file patches in the codex patch format.
#[derive(Debug, Default)]
pub struct ApplyPatchTool;

// ─── Internal types ──────────────────────────────────────────────────

/// A computed file change — all content determined in-memory, ready to write.
enum FileChange {
    Add {
        path: PathBuf,
        content: String,
        /// What the path held before (an Add over an existing file overwrites it).
        prior: PriorContent,
    },
    Delete {
        path: PathBuf,
        /// `None` when the file is not valid UTF-8: it is still deleted, but cannot be snapshotted for rewind.
        original_content: Option<String>,
    },
    Update {
        path: PathBuf,
        original_content: String,
        new_content: String,
    },
    Move {
        source_path: PathBuf,
        dest_path: PathBuf,
        original_content: String,
        new_content: String,
        /// What the destination held before (a Move onto an existing file overwrites it).
        dest_prior: PriorContent,
    },
}

impl FileChange {
    /// Every path this change writes or deletes.
    fn written_paths(&self) -> Vec<&PathBuf> {
        match self {
            Self::Add { path, .. } | Self::Delete { path, .. } | Self::Update { path, .. } => {
                vec![path]
            }
            Self::Move {
                source_path,
                dest_path,
                ..
            } => vec![source_path, dest_path],
        }
    }
}

/// The first path `changes` would write that is not one of the `judged` (approved) targets.
fn first_unjudged_path<'a>(changes: &'a [FileChange], judged: &[PathBuf]) -> Option<&'a PathBuf> {
    changes
        .iter()
        .flat_map(FileChange::written_paths)
        .find(|path| !judged.contains(path))
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Create parent directories for a file path if they don't exist.
async fn ensure_parent_dirs(path: &std::path::Path) -> Result<(), fuigo_tool_runtime::ToolError> {
    ensure_parent_dirs_tracked(path, &mut Vec::new()).await
}

/// [`ensure_parent_dirs`] that also records, top-down, every directory this call had to create (audit review L14), so a
/// patch that then fails can take them away again.
#[allow(clippy::disallowed_methods, reason = "file tool write of a model/user-chosen path (user content); not inside a session folder")]
async fn ensure_parent_dirs_tracked(
    path: &std::path::Path,
    created: &mut Vec<PathBuf>,
) -> Result<(), fuigo_tool_runtime::ToolError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let mut missing: Vec<PathBuf> = Vec::new();
        for dir in parent.ancestors() {
            if dir.as_os_str().is_empty() || tokio::fs::symlink_metadata(dir).await.is_ok() {
                break;
            }
            missing.push(dir.to_path_buf());
        }
        let result = tokio::fs::create_dir_all(parent).await;
        // Record what exists now even when the create stopped part way: those were made by this call.
        for dir in missing.into_iter().rev() {
            if tokio::fs::symlink_metadata(&dir).await.is_ok() {
                created.push(dir);
            }
        }
        result.map_err(|e| {
            fuigo_tool_runtime::ToolError::execution(
                fuigo_tool_protocol::ToolId::new("apply_patch").expect("valid"),
                e.to_string(),
            )
        })?;
    }
    Ok(())
}

/// Remove the directories a failed patch created, deepest first. `remove_dir` only removes an empty directory, so one
/// that holds a file the patch already wrote stays.
#[allow(clippy::disallowed_methods, reason = "file tool cleanup of directories this call created; not inside a session folder")]
async fn remove_created_dirs(created: &[PathBuf]) {
    for dir in created.iter().rev() {
        let _ = tokio::fs::remove_dir(dir).await;
    }
}

/// The files a parsed patch writes, as the model spelled them, in patch order without repeats: every Add, Update and
/// Delete path, and both the source and the destination of a move.
///
/// The permission check judges exactly these, one `Edit` each (P184), at the path this tool writes (`cwd.join(path)`),
/// and [`ApplyPatchTool`] refuses to write any path outside them.
pub fn patch_target_paths(hunks: &[Hunk]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for hunk in hunks {
        let (path, move_path) = match hunk {
            Hunk::AddFile { path, .. } | Hunk::DeleteFile { path } => (path, None),
            Hunk::UpdateFile {
                path, move_path, ..
            } => (path, move_path.as_ref()),
        };
        for target in std::iter::once(path).chain(move_path) {
            let target = target.to_string_lossy().into_owned();
            if !out.contains(&target) {
                out.push(target);
            }
        }
    }
    out
}

/// Parse `patch` and return the files it writes ([`patch_target_paths`]), or the parser's message when it does not
/// parse (the same text the tool returns for it).
pub fn patch_edit_targets(patch: &str) -> Result<Vec<String>, String> {
    parser::parse_patch(patch)
        .map(|parsed| patch_target_paths(&parsed.hunks))
        .map_err(|e| parse_error_message(&e))
}

fn parse_error_message(e: &ParseError) -> String {
    match e {
        ParseError::InvalidPatchError(m) => format!("Invalid patch: {m}"),
        ParseError::InvalidHunkError {
            message,
            line_number,
        } => format!("Invalid patch hunk on line {line_number}: {message}"),
    }
}

/// Compute all file changes in memory without writing anything.
/// Returns an error string if any hunk can't be applied.
async fn compute_all_changes(
    resolve: &(dyn Fn(&std::path::Path) -> PathBuf + Sync),
    fs: &Arc<dyn AsyncFileSystem>,
    hunks: &[Hunk],
) -> Result<Vec<FileChange>, String> {
    let mut changes = Vec::new();

    for hunk in hunks {
        match hunk {
            Hunk::AddFile { path, contents } => {
                let resolved = resolve(path);
                let prior = PriorContent::from_read(read_tool_source(fs.as_ref(), &resolved).await);
                changes.push(FileChange::Add {
                    path: resolved,
                    content: contents.clone(),
                    prior,
                });
            }
            Hunk::DeleteFile { path } => {
                let resolved = resolve(path);
                // Deleting needs no decode: a non-UTF-8 file is still deleted, reported without a snapshot.
                // A file over the source cap is still deleted, reported without a snapshot (audit S4-F7).
                let original_content = match read_tool_source(fs.as_ref(), &resolved).await {
                    Ok(bytes) => String::from_utf8(bytes).ok(),
                    Err(e) if e.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) => None,
                    Err(e) => {
                        return Err(format!("Failed to read file: {}, {e}", resolved.display()));
                    }
                };
                changes.push(FileChange::Delete {
                    path: resolved,
                    original_content,
                });
            }
            Hunk::UpdateFile {
                path,
                move_path,
                chunks,
            } => {
                let resolved = resolve(path);
                let original_content = read_file_as_string(fs, &resolved).await.map_err(|e| {
                    format!("Failed to read file to update: {}, {e}", resolved.display())
                })?;

                let new_content = apply::derive_new_contents(&original_content, &resolved, chunks)
                    .map_err(|e| match e {
                        ApplyPatchError::ComputeReplacements(msg) => msg,
                        other => other.to_string(),
                    })?;

                if let Some(dest) = move_path {
                    let resolved_dest = resolve(dest);
                    if same_file(&resolved, &resolved_dest).await {
                        // A Move onto the file itself (same spelling, or a case-only rename on a case-insensitive
                        // volume) is an in-place update: writing the destination and then deleting the source would
                        // delete the file just written (audit S4-F4).
                        changes.push(FileChange::Update {
                            path: resolved,
                            original_content,
                            new_content,
                        });
                    } else {
                        let dest_prior = PriorContent::from_read(read_tool_source(fs.as_ref(), &resolved_dest).await);
                        changes.push(FileChange::Move {
                            source_path: resolved,
                            dest_path: resolved_dest,
                            original_content,
                            new_content,
                            dest_prior,
                        });
                    }
                } else {
                    changes.push(FileChange::Update {
                        path: resolved,
                        original_content,
                        new_content,
                    });
                }
            }
        }
    }

    Ok(changes)
}

/// The path a change is reported under (a move by its source).
fn change_path(change: &FileChange) -> &std::path::Path {
    match change {
        FileChange::Add { path, .. }
        | FileChange::Delete { path, .. }
        | FileChange::Update { path, .. } => path,
        FileChange::Move { source_path, .. } => source_path,
    }
}

/// What the model reads when a write fails part way through a patch: the files already applied and the ones not,
/// so it can repair the tree instead of guessing (audit S4-F9).
fn partial_failure_message(
    changes: &[FileChange],
    failed: usize,
    error: &str,
    applied: &[ApplyPatchFileResult],
) -> String {
    let mut msg = format!(
        "apply_patch stopped at {}: {error}\n",
        change_path(&changes[failed]).display()
    );
    if applied.is_empty() {
        msg.push_str("Applied: none.\n");
    } else {
        msg.push_str("Applied (already written, not rolled back):\n");
        for r in applied {
            let _ = writeln!(msg, "  {} ({})", r.path.display(), r.action);
        }
    }
    msg.push_str("Not applied:\n");
    for change in &changes[failed..] {
        let _ = writeln!(msg, "  {}", change_path(change).display());
    }
    if matches!(changes[failed], FileChange::Move { .. }) {
        msg.push_str("The failed move may have written its destination before it stopped.\n");
    }
    msg
}

/// Read a file via AsyncFileSystem and convert to String.
async fn read_file_as_string(
    fs: &Arc<dyn AsyncFileSystem>,
    path: &std::path::Path,
) -> Result<String, String> {
    let bytes = read_tool_source(fs.as_ref(), path)
        .await
        .map_err(|e| format!("{e}"))?;
    // Refuse non-UTF-8 content: a lossy decode plus a whole-file rewrite (or a lossy rewind snapshot) would replace
    // every invalid byte in the file (audit S4-F5).
    String::from_utf8(bytes).map_err(|_| {
        "the file is not valid UTF-8, so apply_patch cannot change it without corrupting the other bytes; \
         edit it with a shell command (sed, patch) instead"
            .to_string()
    })
}

/// Whether two paths name the same file: the same path once `.` components are dropped, or, when both exist, the
/// same device and inode (which also catches a case-only rename on a case-insensitive volume and a symlink).
async fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    use std::path::Component;
    let norm = |p: &std::path::Path| -> PathBuf { p.components().filter(|c| *c != Component::CurDir).collect() };
    if norm(a) == norm(b) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(ma), Ok(mb)) = (tokio::fs::metadata(a).await, tokio::fs::metadata(b).await) {
            return ma.dev() == mb.dev() && ma.ino() == mb.ino();
        }
    }
    false
}

/// Build the codex-style summary string.
fn build_summary(results: &[ApplyPatchFileResult]) -> String {
    let mut out = String::from("Success. Updated the following files:\n");
    for r in results {
        let prefix = match r.action.as_str() {
            "added" => "A",
            "deleted" => "D",
            "moved" => "M",
            _ => "M", // "modified"
        };
        let _ = writeln!(out, "{prefix} {}", r.path.display());
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────

impl crate::types::tool_metadata::ToolMetadata for ApplyPatchTool {
    fn kind(&self) -> ToolKind {
        ToolKind::Edit
    }

    fn tool_namespace(&self) -> ToolNamespace {
        ToolNamespace::Codex
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

impl fuigo_tool_runtime::Tool for ApplyPatchTool {
    type Args = ApplyPatchInput;
    type Output = ApplyPatchOutput;

    fn id(&self) -> fuigo_tool_protocol::ToolId {
        fuigo_tool_protocol::ToolId::new("apply_patch").expect("valid tool id")
    }

    fn description(
        &self,
        _ctx: &::fuigo_tool_runtime::ListToolsContext,
    ) -> fuigo_tool_types::ToolDescription {
        fuigo_tool_types::ToolDescription::new(
            "apply_patch",
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

    #[tracing::instrument(name = "tool.apply_patch", skip_all)]
    async fn run(
        &self,
        ctx: fuigo_tool_runtime::ToolCallContext,
        input: ApplyPatchInput,
    ) -> Result<ApplyPatchOutput, fuigo_tool_runtime::ToolError> {
        use crate::types::tool_metadata::shared_resources;
        let resources = shared_resources(&ctx)?;

        let (cwd, fs, notification_handle);
        {
            cwd = crate::types::tool_metadata::resolve_cwd(&ctx, &resources).await?;
            let res = resources.lock().await;
            fs = res.require::<FileSystem>()?.0.clone();
            notification_handle = res.require::<NotificationHandle>()?.0.clone();
        }
        let tool_call_id = ctx.call_id.as_str().to_owned();

        // ── Phase 1: Parse ───────────────────────────────────────
        let parsed = match parser::parse_patch(&input.patch) {
            Ok(p) => p,
            Err(e) => return Ok(ApplyPatchOutput::ParseError(parse_error_message(&e))),
        };

        if parsed.hunks.is_empty() {
            return Ok(ApplyPatchOutput::EmptyPatch(
                "No files were modified.".to_string(),
            ));
        }

        // ── Phase 2: Compute all changes in memory (no writes yet) ───
        // Every path is the cwd join of the patch's spelling, which is the path the permission check judges (P184).
        let resolve = |path: &std::path::Path| cwd.join(path);
        // Hold every target's edit lock from the read to the last write, so a single-file edit of one of these files
        // in the same parallel batch cannot interleave with the patch (audit S4-F9).
        let target_paths: Vec<PathBuf> = patch_target_paths(&parsed.hunks)
            .iter()
            .map(|p| resolve(std::path::Path::new(p)))
            .collect();
        let _edit_locks = crate::util::lock_path::lock_edit_paths(&target_paths, &cwd).await;
        let changes = match compute_all_changes(&resolve, &fs, &parsed.hunks).await {
            Ok(c) => c,
            Err(msg) => return Ok(ApplyPatchOutput::ApplicationError(msg)),
        };
        // Write only what was judged: the permission request carried `patch_target_paths` of this same patch, so a
        // change outside that list (a parser/apply drift) is refused before anything is written.
        let judged: Vec<PathBuf> = patch_target_paths(&parsed.hunks)
            .iter()
            .map(|p| resolve(std::path::Path::new(p)))
            .collect();
        if let Some(unjudged) = first_unjudged_path(&changes, &judged) {
            return Ok(ApplyPatchOutput::ApplicationError(format!(
                "apply_patch refused: {} is not one of the files the patch was approved for",
                unjudged.display()
            )));
        }

        // Make every destination directory before writing any file: a path component that is a file (the usual reason a
        // later write cannot succeed) is found while nothing has changed yet (audit S4-F9).
        let mut created_dirs: Vec<PathBuf> = Vec::new();
        for change in &changes {
            let dest = match change {
                FileChange::Add { path, .. } => path,
                FileChange::Move { dest_path, .. } => dest_path,
                FileChange::Delete { .. } | FileChange::Update { .. } => continue,
            };
            if let Err(e) = ensure_parent_dirs_tracked(dest, &mut created_dirs).await {
                remove_created_dirs(&created_dirs).await;
                return Ok(ApplyPatchOutput::ApplicationError(format!(
                    "apply_patch changed nothing: cannot create the directory for {}: {e}",
                    dest.display()
                )));
            }
        }

        // ── Phase 3: Apply all changes (write to filesystem) ─────
        let mut file_results = Vec::new();

        let applied: Result<(), (usize, String)> = async {
            for (idx, change) in changes.iter().enumerate() {
            match change {
                FileChange::Add {
                    path,
                    content,
                    prior,
                } => {
                    // Create parent directories if needed.
                    ensure_parent_dirs(path).await.map_err(|e| (idx, e.to_string()))?;
                    fs.write_file(path, content.as_bytes()).await.map_err(|e| (idx, e.to_string()))?;

                    notification_handle.send_file_written(FileWritten {
                        tool_call_id: tool_call_id.clone(),
                        absolute_path: path.clone(),
                        content: content.clone(),
                        previous_content: prior.previous_content(),
                        is_new_file: prior.is_new_file(),
                    });

                    file_results.push(ApplyPatchFileResult {
                        path: path.clone(),
                        action: "added".to_string(),
                        old_text: None,
                        new_text: content.clone(),
                        move_to: None,
                    });
                }
                FileChange::Delete {
                    path,
                    original_content,
                } => {
                    fs.delete_file(path).await.map_err(|e| (idx, e.to_string()))?;

                    notification_handle.send_file_written(FileWritten {
                        tool_call_id: tool_call_id.clone(),
                        absolute_path: path.clone(),
                        content: String::new(),
                        previous_content: original_content.clone(),
                        is_new_file: false,
                    });

                    file_results.push(ApplyPatchFileResult {
                        path: path.clone(),
                        action: "deleted".to_string(),
                        old_text: original_content.clone(),
                        new_text: String::new(),
                        move_to: None,
                    });
                }
                FileChange::Update {
                    path,
                    original_content,
                    new_content,
                } => {
                    fs.write_file(path, new_content.as_bytes())
                        .await
                        .map_err(|e| (idx, e.to_string()))?;

                    notification_handle.send_file_written(FileWritten {
                        tool_call_id: tool_call_id.clone(),
                        absolute_path: path.clone(),
                        content: new_content.clone(),
                        previous_content: Some(original_content.clone()),
                        is_new_file: false,
                    });

                    file_results.push(ApplyPatchFileResult {
                        path: path.clone(),
                        action: "modified".to_string(),
                        old_text: Some(original_content.clone()),
                        new_text: new_content.clone(),
                        move_to: None,
                    });
                }
                FileChange::Move {
                    source_path,
                    dest_path,
                    original_content,
                    new_content,
                    dest_prior,
                } => {
                    // Create parent dirs for destination.
                    ensure_parent_dirs(dest_path).await.map_err(|e| (idx, e.to_string()))?;
                    fs.write_file(dest_path, new_content.as_bytes())
                        .await
                        .map_err(|e| (idx, e.to_string()))?;
                    fs.delete_file(source_path).await.map_err(|e| (idx, e.to_string()))?;

                    // Notify destination (new file at new location).
                    notification_handle.send_file_written(FileWritten {
                        tool_call_id: tool_call_id.clone(),
                        absolute_path: dest_path.clone(),
                        content: new_content.clone(),
                        previous_content: dest_prior.previous_content(),
                        is_new_file: dest_prior.is_new_file(),
                    });
                    // Notify source (deleted).
                    notification_handle.send_file_written(FileWritten {
                        tool_call_id: tool_call_id.clone(),
                        absolute_path: source_path.clone(),
                        content: String::new(),
                        previous_content: Some(original_content.clone()),
                        is_new_file: false,
                    });

                    file_results.push(ApplyPatchFileResult {
                        path: source_path.clone(),
                        action: "moved".to_string(),
                        old_text: Some(original_content.clone()),
                        new_text: new_content.clone(),
                        move_to: Some(dest_path.clone()),
                    });
                }
            }
            }
            Ok(())
        }
        .await;
        if let Err((idx, error)) = applied {
            remove_created_dirs(&created_dirs).await;
            return Ok(ApplyPatchOutput::ApplicationError(partial_failure_message(
                &changes,
                idx,
                &error,
                &file_results,
            )));
        }

        // ── Phase 4: Build summary ───────────────────────────────
        let tool_output_for_prompt = build_summary(&file_results);

        Ok(ApplyPatchOutput::Success {
            files: file_results,
            tool_output_for_prompt,
        })
    }
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer::local::LocalFs;
    use crate::notification::types::ToolNotificationHandle;
    use crate::types::resources::Resources;
    use crate::types::tool_metadata::test_ctx;
    use tempfile::TempDir;

    /// Set up Resources with real filesystem for tests.
    fn test_resources(cwd: &std::path::Path) -> Resources {
        let mut resources = Resources::new();
        resources.insert(Cwd(cwd.to_path_buf()));
        resources.insert(FileSystem(Arc::new(LocalFs)));
        resources.insert(NotificationHandle(ToolNotificationHandle::noop()));
        resources
    }

    /// Build a runtime `ToolCallContext` with the given shared resources.
    fn make_input(patch: &str) -> ApplyPatchInput {
        ApplyPatchInput {
            patch: patch.to_string(),
        }
    }

    /// The input accepts the JSON function form and every freeform envelope: a bare string (a Responses
    /// `custom_tool_call` input), and the `raw` / `input` wrappers the shell uses for non-JSON arguments.
    #[test]
    fn input_accepts_json_form_and_raw_freeform_text() {
        let patch = "*** Begin Patch\n*** Add File: a.txt\n+hi\n*** End Patch\n";
        for value in [
            serde_json::json!({ "patch": patch }),
            serde_json::json!({ "raw": patch }),
            serde_json::json!({ "input": patch }),
            serde_json::Value::String(patch.to_string()),
        ] {
            let input: ApplyPatchInput =
                serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{value}: {e}"));
            assert_eq!(input.patch, patch, "{value}");
        }
        assert!(serde_json::from_value::<ApplyPatchInput>(serde_json::json!({ "other": 1 })).is_err());
        // The schema advertised to JSON backends is unchanged: an object with a required `patch` string
        let schema = serde_json::to_value(schemars::schema_for!(ApplyPatchInput)).unwrap();
        assert_eq!(schema["required"], serde_json::json!(["patch"]));
    }

    /// The grammar is Codex's, byte for byte on the lines that matter, and the description says freeform.
    #[test]
    fn freeform_grammar_matches_codex() {
        assert!(APPLY_PATCH_LARK_GRAMMAR.starts_with("start: begin_patch hunk+ end_patch\n"));
        assert!(APPLY_PATCH_LARK_GRAMMAR.contains("add_line: \"+\" /(.*)/ LF -> line\n"));
        assert!(APPLY_PATCH_LARK_GRAMMAR.contains("change_line: (\"+\" | \"-\" | \" \") /(.*)/ LF\n"));
        assert!(APPLY_PATCH_LARK_GRAMMAR.ends_with("%import common.LF\n"));
        assert!(APPLY_PATCH_FREEFORM_DESCRIPTION.contains("FREEFORM"));
    }

    fn wrap_patch(body: &str) -> String {
        format!("*** Begin Patch\n{body}\n*** End Patch")
    }

    // ── Add file ─────────────────────────────────────────────────

    #[tokio::test]
    async fn add_file_creates_with_correct_content() {
        let tmp = TempDir::new().unwrap();
        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = wrap_patch("*** Add File: new.txt\n+hello\n+world");
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(&patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::Success {
                files,
                tool_output_for_prompt,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].action, "added");
                assert!(tool_output_for_prompt.contains("A "));
                let content = std::fs::read_to_string(tmp.path().join("new.txt")).unwrap();
                assert_eq!(content, "hello\nworld\n");
            }
            other => panic!("Expected Success, got: {other:?}"),
        }
    }

    // ── Delete file ──────────────────────────────────────────────

    #[tokio::test]
    async fn delete_file_removes_file() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("del.txt"), "content").unwrap();

        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = wrap_patch("*** Delete File: del.txt");
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(&patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::Success {
                files,
                tool_output_for_prompt,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].action, "deleted");
                assert!(tool_output_for_prompt.contains("D "));
                assert!(!tmp.path().join("del.txt").exists());
            }
            other => panic!("Expected Success, got: {other:?}"),
        }
    }

    // ── Update file ──────────────────────────────────────────────

    #[tokio::test]
    async fn update_file_modifies_content() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("update.txt"), "foo\nbar\n").unwrap();

        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = wrap_patch("*** Update File: update.txt\n@@\n foo\n-bar\n+baz");
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(&patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::Success {
                files,
                tool_output_for_prompt,
            } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].action, "modified");
                assert!(tool_output_for_prompt.contains("M "));
                let content = std::fs::read_to_string(tmp.path().join("update.txt")).unwrap();
                assert_eq!(content, "foo\nbaz\n");
            }
            other => panic!("Expected Success, got: {other:?}"),
        }
    }

    // ── Move file ────────────────────────────────────────────────

    #[tokio::test]
    async fn move_file_renames_and_modifies() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("src.txt"), "line\n").unwrap();

        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = wrap_patch("*** Update File: src.txt\n*** Move to: dst.txt\n@@\n-line\n+line2");
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(&patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::Success { files, .. } => {
                assert_eq!(files.len(), 1);
                assert_eq!(files[0].action, "moved");
                assert_eq!(files[0].move_to, Some(tmp.path().join("dst.txt")));
                assert!(!tmp.path().join("src.txt").exists());
                let content = std::fs::read_to_string(tmp.path().join("dst.txt")).unwrap();
                assert_eq!(content, "line2\n");
            }
            other => panic!("Expected Success, got: {other:?}"),
        }
    }

    // ── Multiple files in one patch ──────────────────────────────

    #[tokio::test]
    async fn multiple_files_in_one_patch() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("existing.txt"), "old\n").unwrap();

        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = wrap_patch(
            "*** Add File: a.txt\n+aaa\n\
             *** Add File: b.txt\n+bbb",
        );
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(&patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::Success {
                files,
                tool_output_for_prompt,
            } => {
                assert_eq!(files.len(), 2);
                assert!(tool_output_for_prompt.contains("A "));
                assert_eq!(
                    std::fs::read_to_string(tmp.path().join("a.txt")).unwrap(),
                    "aaa\n"
                );
                assert_eq!(
                    std::fs::read_to_string(tmp.path().join("b.txt")).unwrap(),
                    "bbb\n"
                );
            }
            other => panic!("Expected Success, got: {other:?}"),
        }
    }

    // ── P184: targets and path resolution ───────────────────────

    /// The permission check judges `patch_target_paths`: every Add, Update and Delete path and both ends of a move, in
    /// patch order, each once.
    #[test]
    fn patch_target_paths_lists_every_written_path_once() {
        let patch = wrap_patch(
            "*** Add File: a.txt\n+x\n*** Delete File: b.txt\n*** Update File: c.txt\n*** Move to: d/e.txt\n@@\n-o\n+n\n*** Update File: a.txt\n@@\n-x\n+y",
        );
        assert_eq!(
            patch_edit_targets(&patch).unwrap(),
            vec!["a.txt", "b.txt", "c.txt", "d/e.txt"]
        );
        let err = patch_edit_targets("not a valid patch").unwrap_err();
        assert!(err.contains("Invalid patch"), "{err}");
        assert_eq!(patch_edit_targets("*** Begin Patch\n*** End Patch").unwrap(), Vec::<String>::new());
    }

    /// The write-only-what-was-judged guard finds a change outside the approved list, including either end of a move.
    #[test]
    fn unjudged_change_is_found_before_any_write() {
        let change = |src: &str, dest: Option<&str>| match dest {
            Some(dest) => FileChange::Move {
                source_path: PathBuf::from(src),
                dest_path: PathBuf::from(dest),
                original_content: String::new(),
                new_content: String::new(),
                dest_prior: PriorContent::Absent,
            },
            None => FileChange::Add {
                path: PathBuf::from(src),
                content: String::new(),
                prior: PriorContent::Absent,
            },
        };
        let judged = vec![PathBuf::from("/w/a"), PathBuf::from("/w/b")];
        let ok = [change("/w/a", None), change("/w/b", None)];
        assert_eq!(first_unjudged_path(&ok, &judged), None);
        let extra = [change("/w/a", None), change("/w/c", None)];
        assert_eq!(first_unjudged_path(&extra, &judged), Some(&PathBuf::from("/w/c")));
        let moved = [change("/w/a", Some("/w/.git/hooks/x"))];
        assert_eq!(
            first_unjudged_path(&moved, &judged),
            Some(&PathBuf::from("/w/.git/hooks/x"))
        );
    }

    /// The tool writes the cwd join of the patch's spelling, which is what the permission check judges: a name with a
    /// quote is that file, not a quote-stripped neighbour.
    #[tokio::test]
    async fn literal_names_are_written_as_judged() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("report"), "keep\n").unwrap();
        std::fs::write(tmp.path().join("report'"), "drop\n").unwrap();
        let shared = test_resources(tmp.path()).into_shared();
        let patch = wrap_patch("*** Delete File: report'");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
            .await
            .unwrap();
        assert!(matches!(result, ApplyPatchOutput::Success { .. }), "{result:?}");
        assert!(!tmp.path().join("report'").exists());
        assert_eq!(std::fs::read_to_string(tmp.path().join("report")).unwrap(), "keep\n");
    }

    // ── Parse error ──────────────────────────────────────────────

    #[tokio::test]
    async fn parse_error_returns_no_changes() {
        let tmp = TempDir::new().unwrap();
        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let result = fuigo_tool_runtime::Tool::run(
            &tool,
            test_ctx(shared.clone()),
            make_input("not a valid patch"),
        )
        .await
        .unwrap();

        match result {
            ApplyPatchOutput::ParseError(msg) => {
                assert!(msg.contains("Invalid patch"));
            }
            other => panic!("Expected ParseError, got: {other:?}"),
        }
    }

    // ── Application error ────────────────────────────────────────

    #[tokio::test]
    async fn application_error_on_missing_lines() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file.txt"), "actual\n").unwrap();

        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = wrap_patch("*** Update File: file.txt\n@@\n-nonexistent\n+replacement");
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(&patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::ApplicationError(msg) => {
                assert!(msg.contains("Failed to find expected lines"));
            }
            other => panic!("Expected ApplicationError, got: {other:?}"),
        }
    }

    // ── Empty patch ──────────────────────────────────────────────

    #[tokio::test]
    async fn empty_patch_returns_empty_patch_output() {
        let tmp = TempDir::new().unwrap();
        let tool = ApplyPatchTool;
        let resources = test_resources(tmp.path());
        let shared = resources.into_shared();

        let patch = "*** Begin Patch\n*** End Patch";
        let result =
            fuigo_tool_runtime::Tool::run(&tool, test_ctx(shared.clone()), make_input(patch))
                .await
                .unwrap();

        match result {
            ApplyPatchOutput::EmptyPatch(msg) => {
                assert!(msg.contains("No files were modified"));
            }
            other => panic!("Expected EmptyPatch, got: {other:?}"),
        }
    }

    // ── Audit S4-F3 / F4 / F5 ────────────────────────────────────

    fn resources_with_channel(
        cwd: &std::path::Path,
    ) -> (
        SharedResources,
        tokio::sync::mpsc::UnboundedReceiver<crate::notification::types::ToolNotification>,
    ) {
        let (handle, rx) = ToolNotificationHandle::channel();
        let mut resources = test_resources(cwd);
        resources.insert(NotificationHandle(handle));
        (resources.into_shared(), rx)
    }

    fn written(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::notification::types::ToolNotification>,
    ) -> Vec<FileWritten> {
        let mut out = Vec::new();
        while let Ok(n) = rx.try_recv() {
            if let crate::notification::types::ToolNotification::FileWritten(w) = n {
                out.push(w);
            }
        }
        out
    }

    #[tokio::test]
    async fn move_onto_same_file_keeps_the_file() {
        for dest in ["a.txt", "./a.txt"] {
            let tmp = TempDir::new().unwrap();
            std::fs::write(tmp.path().join("a.txt"), "old\n").unwrap();
            let shared = test_resources(tmp.path()).into_shared();
            let patch = wrap_patch(&format!(
                "*** Update File: a.txt\n*** Move to: {dest}\n@@\n-old\n+new"
            ));
            let result =
                fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
                    .await
                    .unwrap();
            assert!(matches!(result, ApplyPatchOutput::Success { .. }), "{dest}: {result:?}");
            assert_eq!(std::fs::read_to_string(tmp.path().join("a.txt")).unwrap(), "new\n", "{dest}");
        }
    }

    #[tokio::test]
    async fn add_over_existing_file_reports_previous_content() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "orig\n").unwrap();
        let (shared, mut rx) = resources_with_channel(tmp.path());
        let patch = wrap_patch("*** Add File: a.txt\n+fresh");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
            .await
            .unwrap();
        assert!(matches!(result, ApplyPatchOutput::Success { .. }), "{result:?}");
        let w = written(&mut rx);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].previous_content.as_deref(), Some("orig\n"));
        assert!(!w[0].is_new_file);
    }

    #[tokio::test]
    async fn move_onto_existing_file_reports_previous_content() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "old\n").unwrap();
        std::fs::write(tmp.path().join("b.txt"), "theirs\n").unwrap();
        let (shared, mut rx) = resources_with_channel(tmp.path());
        let patch = wrap_patch("*** Update File: a.txt\n*** Move to: b.txt\n@@\n-old\n+new");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
            .await
            .unwrap();
        assert!(matches!(result, ApplyPatchOutput::Success { .. }), "{result:?}");
        let dest = written(&mut rx)
            .into_iter()
            .find(|w| w.absolute_path.ends_with("b.txt"))
            .unwrap();
        assert_eq!(dest.previous_content.as_deref(), Some("theirs\n"));
        assert!(!dest.is_new_file);
    }

    #[tokio::test]
    async fn add_over_non_utf8_file_is_not_reported_as_new_or_lossy() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.bin"), b"x\xff\n").unwrap();
        let (shared, mut rx) = resources_with_channel(tmp.path());
        let patch = wrap_patch("*** Add File: a.bin\n+fresh");
        let _ = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
            .await
            .unwrap();
        let w = written(&mut rx);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].previous_content, None);
        assert!(!w[0].is_new_file);
    }

    #[tokio::test]
    async fn update_of_non_utf8_file_is_refused_and_leaves_bytes() {
        let tmp = TempDir::new().unwrap();
        let original: &[u8] = b"one\n\xff\xfe\nthree\n";
        std::fs::write(tmp.path().join("l.txt"), original).unwrap();
        let shared = test_resources(tmp.path()).into_shared();
        let patch = wrap_patch("*** Update File: l.txt\n@@\n-one\n+uno");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
            .await
            .unwrap();
        assert!(matches!(result, ApplyPatchOutput::ApplicationError(_)), "{result:?}");
        assert_eq!(std::fs::read(tmp.path().join("l.txt")).unwrap(), original);
    }

    #[tokio::test]
    async fn delete_of_non_utf8_file_still_deletes() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("a.bin"), b"x\xff\n").unwrap();
        let (shared, mut rx) = resources_with_channel(tmp.path());
        let patch = wrap_patch("*** Delete File: a.bin");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch))
            .await
            .unwrap();
        assert!(matches!(result, ApplyPatchOutput::Success { .. }), "{result:?}");
        assert!(!tmp.path().join("a.bin").exists());
        let w = written(&mut rx);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].previous_content, None);
        assert!(!w[0].is_new_file);
    }

    /// A file system that refuses to write one named file, to fail a patch part way through its writes.
    struct FailsOn(&'static str);
    #[async_trait::async_trait]
    impl AsyncFileSystem for FailsOn {
        async fn read_file(&self, path: &std::path::Path) -> Result<Vec<u8>, crate::computer::types::ComputerError> {
            LocalFs.read_file(path).await
        }
        async fn write_file(
            &self,
            path: &std::path::Path,
            data: &[u8],
        ) -> Result<(), crate::computer::types::ComputerError> {
            if path.ends_with(self.0) {
                return Err(crate::computer::types::ComputerError::io_with_kind(
                    "injected write failure",
                    std::io::ErrorKind::PermissionDenied,
                ));
            }
            LocalFs.write_file(path, data).await
        }
        async fn delete_file(&self, path: &std::path::Path) -> Result<(), crate::computer::types::ComputerError> {
            LocalFs.delete_file(path).await
        }
    }

    /// Audit S4-F9: a write that fails part way reports exactly which files were applied and which were not.
    #[tokio::test]
    async fn a_failed_write_lists_applied_and_unapplied_files() {
        let tmp = TempDir::new().unwrap();
        let mut resources = test_resources(tmp.path());
        resources.insert(FileSystem(Arc::new(FailsOn("b.txt"))));
        let patch = wrap_patch(
            "*** Add File: a.txt\n+one\n*** Add File: b.txt\n+two\n*** Add File: c.txt\n+three",
        );
        let result = fuigo_tool_runtime::Tool::run(
            &ApplyPatchTool,
            test_ctx(resources.into_shared()),
            make_input(&patch),
        )
        .await
        .unwrap();
        let ApplyPatchOutput::ApplicationError(msg) = result else {
            panic!("expected an application error naming the files, got {result:?}");
        };
        assert!(msg.contains("Applied") && msg.contains("a.txt"), "{msg}");
        assert!(msg.contains("Not applied") && msg.contains("b.txt") && msg.contains("c.txt"), "{msg}");
        assert!(tmp.path().join("a.txt").exists());
        assert!(!tmp.path().join("c.txt").exists());
    }

    /// Audit S4-F9: a destination whose directory cannot be created is found before any file is written.
    #[tokio::test]
    async fn an_uncreatable_destination_directory_leaves_every_file_untouched() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("blocker"), "a file, not a directory").unwrap();
        let shared = test_resources(tmp.path()).into_shared();
        let patch = wrap_patch("*** Add File: a.txt\n+one\n*** Add File: blocker/x.txt\n+two");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch)).await;
        assert!(!matches!(result, Ok(ApplyPatchOutput::Success { .. })), "{result:?}");
        assert!(!tmp.path().join("a.txt").exists(), "nothing is written when a later target cannot be");
    }

    /// Audit review L14: directories made ahead of a patch that then cannot be applied do not stay behind.
    #[tokio::test]
    async fn an_uncreatable_destination_removes_the_directories_made_before_it() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("blocker"), "a file, not a directory").unwrap();
        let shared = test_resources(tmp.path()).into_shared();
        let patch = wrap_patch("*** Add File: deep/er/a.txt\n+one\n*** Add File: blocker/x.txt\n+two");
        let result = fuigo_tool_runtime::Tool::run(&ApplyPatchTool, test_ctx(shared), make_input(&patch)).await;
        assert!(!matches!(result, Ok(ApplyPatchOutput::Success { .. })), "{result:?}");
        assert!(!tmp.path().join("deep").exists(), "directories this call created are removed");
        assert!(tmp.path().join("blocker").is_file());
    }

    /// Audit review L14: a write that fails leaves no empty directory this call made; a directory holding an applied
    /// file, or one that existed before, stays.
    #[tokio::test]
    async fn a_failed_write_removes_empty_directories_it_created_only() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("old")).unwrap();
        let mut resources = test_resources(tmp.path());
        resources.insert(FileSystem(Arc::new(FailsOn("b.txt"))));
        let patch = wrap_patch(
            "*** Add File: keep/a.txt\n+one\n*** Add File: old/new/b.txt\n+two\n*** Add File: gone/er/c.txt\n+three",
        );
        let result = fuigo_tool_runtime::Tool::run(
            &ApplyPatchTool,
            test_ctx(resources.into_shared()),
            make_input(&patch),
        )
        .await
        .unwrap();
        assert!(matches!(result, ApplyPatchOutput::ApplicationError(_)), "{result:?}");
        assert!(tmp.path().join("keep/a.txt").exists(), "an applied file stays with its directory");
        assert!(tmp.path().join("old").is_dir(), "a directory that existed before stays");
        assert!(!tmp.path().join("old/new").exists());
        assert!(!tmp.path().join("gone").exists());
    }
}
