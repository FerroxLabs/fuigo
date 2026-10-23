//! Resume-by-title selection shared by startup paths.
//!
//! The composition root pins an explicit non-id resume target to its canonical session id BEFORE the irreversible OS sandbox
//! ([`super::cli::PagerArgs::pin_local_resume_target`]).
//! That way the saved-profile peek and materialization act on one immutable target instead of racing a concurrent rename between two title lookups.
//! Materialization keeps [`select_by_title`] as the authoritative error source (ambiguity / no-match).
//! It is also the fallback for callers that bypass pinning.

use fuigo_shell::session::persistence::{RecentSessionSelection, Summary};

/// UUID-shaped resume args always take the id path, even when no such id exists and a session is titled with that exact UUID.
pub(crate) fn is_uuid_shaped(arg: &str) -> bool {
    uuid::Uuid::try_parse(arg).is_ok()
}

/// The lowercased words of a title or typed text: whatever is not a letter or digit separates them, so
/// `fix-login-bug`, `fix_login_bug` and `Fix login bug` are the same words.
/// Plain `str::to_lowercase` per word, not full Unicode caseless matching.
fn title_words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// Canonical key for title equality: the words of [`title_words`] joined by single spaces.
/// Text with no letters or digits at all falls back to its trimmed lowercase form, so a title like `???` stays findable.
fn title_key(s: &str) -> String {
    let words = title_words(s);
    if words.is_empty() {
        s.trim().to_lowercase()
    } else {
        words.join(" ")
    }
}

/// Newest change first (`last_active_at`, else `updated_at`).
fn newest_first(found: &mut [&Summary]) {
    found.sort_by_key(|s| std::cmp::Reverse(s.last_change_unix_ms()));
}

/// When the session last changed, for a listing.
fn updated_label(s: &Summary) -> String {
    chrono::DateTime::from_timestamp_millis(s.last_change_unix_ms())
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Hint appended to every terminal failure for a non-id resume target.
/// The title miss stays visible even when remote restore produces the final error.
/// Debug formatting: the arg is arbitrary user text.
pub(crate) fn title_miss_hint(arg: &str) -> String {
    format!(
        "no session id or title matched {arg:?} for this directory; \
         try `fuigo sessions search {arg:?}`"
    )
}

/// Select the local session a resume arg names by title.
///
/// - `Ok(None)`: UUID-shaped or blank arg, or no title matched; the caller keeps id-miss behavior.
/// - `Ok(Some)`: exactly one match, or a sole manual `/rename` among duplicates (explicit user intent beats colliding auto titles).
/// - `Err`: ambiguous; never silently pick one, headless scripts need determinism.
///   Candidate titles are Debug-escaped: `/rename` accepts arbitrary text, and raw control characters would corrupt the listing.
pub(crate) fn select_by_title<'a>(
    arg: &str,
    summaries: &'a [Summary],
) -> anyhow::Result<Option<&'a Summary>> {
    if is_uuid_shaped(arg) {
        return Ok(None);
    }
    let needle = title_key(arg);
    if needle.is_empty() {
        return Ok(None);
    }
    let matches: Vec<&Summary> = summaries
        .iter()
        .filter(|s| title_key(s.display_title()) == needle)
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [only] => Ok(Some(*only)),
        _ => {
            let manual: Vec<&&Summary> = matches
                .iter()
                .filter(|s| {
                    s.manual_title_opt()
                        .is_some_and(|t| title_key(&t) == needle)
                })
                .collect();
            if let [only] = manual.as_slice() {
                return Ok(Some(**only));
            }
            let mut newest = matches.clone();
            newest_first(&mut newest);
            let listing = newest
                .iter()
                .map(|s| {
                    format!(
                        "  {}  {:?}  (updated {})",
                        s.info.id,
                        s.display_title(),
                        updated_label(s)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!(
                "Multiple sessions match title {:?}:\n{listing}\n\
                 Resume by session id instead: fuigo --resume <session-id>",
                arg.trim()
            );
        }
    }
}

/// Sessions a `/resume <text>` could mean, newest first.
/// An exact title match (separators and case ignored) wins outright, with a sole manual rename beating colliding auto titles.
/// Otherwise every session whose title holds every word of `arg`, in any order, qualifies.
pub(crate) fn resume_candidates<'a>(arg: &str, summaries: &'a [Summary]) -> Vec<&'a Summary> {
    let needle = title_key(arg);
    if needle.is_empty() {
        return Vec::new();
    }
    let mut exact: Vec<&Summary> = summaries
        .iter()
        .filter(|s| title_key(s.display_title()) == needle)
        .collect();
    if !exact.is_empty() {
        let manual: Vec<&Summary> = exact
            .iter()
            .copied()
            .filter(|s| s.manual_title_opt().is_some_and(|t| title_key(&t) == needle))
            .collect();
        if let [only] = manual.as_slice() {
            return vec![*only];
        }
        newest_first(&mut exact);
        return exact;
    }
    let wanted = title_words(arg);
    let mut hits: Vec<&Summary> = summaries
        .iter()
        .filter(|s| {
            let have = title_words(s.display_title());
            wanted.iter().all(|w| have.iter().any(|h| h.contains(w.as_str())))
        })
        .collect();
    newest_first(&mut hits);
    hits
}

/// Up to `limit` sessions whose titles share at least one word with `arg`, best match first (ties newest first).
/// Used to suggest something when `arg` matched nothing.
pub(crate) fn similar_titles<'a>(
    arg: &str,
    summaries: &'a [Summary],
    limit: usize,
) -> Vec<&'a Summary> {
    let wanted = title_words(arg);
    if wanted.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(usize, &Summary)> = summaries
        .iter()
        .filter_map(|s| {
            let have = title_words(s.display_title());
            let shared = wanted
                .iter()
                .filter(|w| have.iter().any(|h| h.contains(w.as_str())))
                .count();
            (shared > 0).then_some((shared, s))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.last_change_unix_ms().cmp(&a.1.last_change_unix_ms()))
    });
    scored.into_iter().take(limit).map(|(_, s)| s).collect()
}

/// [`title_miss_hint`], plus the closest existing titles when there are any.
pub(crate) fn title_miss_hint_with(arg: &str, similar: &[&Summary]) -> String {
    let base = title_miss_hint(arg);
    if similar.is_empty() {
        return base;
    }
    let list = similar
        .iter()
        .map(|s| format!("{:?} ({})", s.display_title(), s.info.id))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{base}; similar titles: {list}")
}

/// [`title_miss_hint_with`] for the local sessions of `cwd`.
pub(crate) fn title_miss_hint_for(arg: &str, cwd: &str, selection: RecentSessionSelection) -> String {
    match fuigo_shell::session::persistence::local_summaries_for_cwd_sync(cwd, selection) {
        Ok(all) => title_miss_hint_with(arg, &similar_titles(arg, &all, 3)),
        Err(_) => title_miss_hint(arg),
    }
}

/// Outcome of the pre-sandbox resolution of an explicit resume arg.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PinnedResumeTarget {
    /// Nothing local resolved (UUID-shaped, no cwd, junk, or ambiguous title): leave the raw arg alone.
    /// Materialization owns the authoritative error / remote path.
    Unresolved,
    /// Resolved as a local id (possibly the restored child of a remote id).
    Id(String),
    /// Resolved by title to this session. The selected summary's persisted sandbox profile rides along.
    /// Re-deriving the profile from the id is ambiguous when a legacy id is duplicated across cwd dirs.
    Title {
        id: String,
        sandbox_profile: Option<String>,
    },
}

impl PinnedResumeTarget {
    pub(crate) fn id(self) -> Option<String> {
        match self {
            Self::Unresolved => None,
            Self::Id(id) | Self::Title { id, .. } => Some(id),
        }
    }
}

/// Resolve an explicit resume arg to a pinned local session id before the (irreversible) OS sandbox.
/// The saved-profile peek and materialization must consume one immutable target, not re-run title selection against mutable summaries.
/// Id lookups stay authoritative (same order as `resolve_existing_session`).
/// That preserves the restored-child id so the peek cannot drift to a same-id session in another cwd.
/// Errs on a listing failure (fail closed instead of guessing) and on ambiguity, which must be reported before the sandbox rather than after it.
pub(crate) fn presandbox_resume_target(
    arg: &str,
    cwd: Option<&str>,
    selection: RecentSessionSelection,
) -> anyhow::Result<PinnedResumeTarget> {
    if is_uuid_shaped(arg) {
        return Ok(PinnedResumeTarget::Unresolved);
    }
    let Some(cwd) = cwd else {
        return Ok(PinnedResumeTarget::Unresolved);
    };
    if let Some(local_id) = fuigo_shell::session::resolve_local_session(arg, cwd) {
        return Ok(PinnedResumeTarget::Id(local_id));
    }
    if fuigo_shell::session::resolve_local_session_any_cwd(arg).is_some() {
        return Ok(PinnedResumeTarget::Id(arg.to_string()));
    }
    let summaries = fuigo_shell::session::persistence::local_summaries_for_cwd_sync(cwd, selection)
        .map_err(|e| {
            anyhow::anyhow!("failed to list local sessions while resolving --resume {arg:?}: {e}")
        })?;
    Ok(select_by_title(arg, &summaries)?
        .map(|s| PinnedResumeTarget::Title {
            id: s.info.id.to_string(),
            sandbox_profile: s.sandbox_profile.clone(),
        })
        .unwrap_or(PinnedResumeTarget::Unresolved))
}

/// Failure message for a worktree resume.
/// `local_miss_target` is `Some(arg)` only when materialization deferred exactly this target after missing local id/title resolution.
/// Provenance is threaded, never inferred from id shape, so a resolved legacy non-UUID id gets no false no-match hint.
/// `detail` must already be user-sanitized: sanitizing the composed message would collapse disk-full chains whole and erase the appended hint.
pub(crate) fn worktree_resume_failure_message(
    local_miss_target: Option<&str>,
    detail: &str,
) -> String {
    let msg = format!("couldn't resume worktree session: {detail}");
    match local_miss_target {
        Some(target) => format!("{msg}; {}", title_miss_hint(target)),
        None => msg,
    }
}

#[cfg(test)]
#[path = "session_title_resolve_tests.rs"]
mod tests;
