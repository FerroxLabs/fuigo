//! Turn deltas come from this process's last applied live ledger, not from persisted session totals (those stay large after resume).

use fuigo_chat_state::UsageLedger;
use fuigo_sampling_types::reported_cost_ticks;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Per-turn rows kept in `usage.json` (audit 1.0.47 F4: it is rewritten whole every turn). Older rows move, append-only,
/// to [`USAGE_ARCHIVE_FILE`]; the session totals and `turnCount` still cover every turn.
pub const MAX_TURN_ROWS: usize = 200;

/// One JSON [`TurnUsage`] per line: the rows drained from `usage.json` (F4). A row also in `usage.json`, or repeated
/// here by a crash between the append and the rewrite, is read once: the `usage.json` row, else the last line.
pub const USAGE_ARCHIVE_FILE: &str = "usage_turns.jsonl";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUsageFile {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub updated_at: String,
    #[serde(default)]
    pub session: UsageSummary,
    #[serde(default)]
    pub turns: Vec<TurnUsage>,
    #[serde(skip)]
    last_incoming_turn: Option<u32>,
    #[serde(skip)]
    last_written_turn: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageSummary {
    #[serde(default)]
    pub input_tokens: u64,
    #[serde(default)]
    pub output_tokens: u64,
    #[serde(default)]
    pub cached_read_tokens: u64,
    #[serde(default)]
    pub cache_creation_tokens: u64,
    #[serde(default)]
    pub reasoning_tokens: u64,
    #[serde(default)]
    pub total_tokens: u64,
    #[serde(default)]
    pub model_calls: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd_ticks: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cost_is_partial: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub usage_is_incomplete: bool,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub turn_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_model_id: Option<String>,
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub model_usage: IndexMap<String, UsageSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TurnUsage {
    pub turn_number: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ended_at: String,
    #[serde(flatten)]
    pub usage: UsageSummary,
}

impl UsageSummary {
    pub fn from_ledger(ledger: &UsageLedger) -> Self {
        let mut model_usage = IndexMap::new();
        for (model, totals) in &ledger.by_model {
            model_usage.insert(model.clone(), Self::from_totals(totals, ledger.incomplete));
        }
        let mut summary = Self::from_totals(&ledger.totals, ledger.incomplete);
        summary.primary_model_id = primary_model(&model_usage);
        summary.model_usage = model_usage;
        summary
    }

    fn from_totals(totals: &fuigo_chat_state::UsageTotals, incomplete: bool) -> Self {
        Self {
            input_tokens: totals.input_tokens,
            output_tokens: totals.output_tokens,
            cached_read_tokens: totals.cached_read_tokens,
            cache_creation_tokens: totals.cache_creation_tokens,
            reasoning_tokens: totals.reasoning_tokens,
            total_tokens: totals.total_tokens(),
            model_calls: totals.model_calls,
            cost_usd_ticks: totals.cost_usd_ticks,
            cost_is_partial: totals.cost_is_partial(),
            usage_is_incomplete: incomplete,
            turn_count: 0,
            primary_model_id: None,
            model_usage: IndexMap::new(),
        }
    }

    /// True when `self` is a same-process continuation of `previous` (no bucket shrank), so the turn delta is a subtract, not a full clone.
    pub fn covers(&self, previous: &Self) -> bool {
        self.input_tokens >= previous.input_tokens
            && self.output_tokens >= previous.output_tokens
            && self.model_calls >= previous.model_calls
    }

    pub fn saturating_add(&self, other: &Self) -> Self {
        let mut model_usage = self.model_usage.clone();
        for (model, row) in &other.model_usage {
            let entry = model_usage.entry(model.clone()).or_default();
            *entry = entry.saturating_add_row(row);
        }
        let mut out = self.saturating_add_row(other);
        out.primary_model_id = primary_model(&model_usage);
        out.model_usage = model_usage;
        out.turn_count = self.turn_count.saturating_add(other.turn_count);
        out
    }

    fn saturating_add_row(&self, other: &Self) -> Self {
        Self {
            input_tokens: self.input_tokens.saturating_add(other.input_tokens),
            output_tokens: self.output_tokens.saturating_add(other.output_tokens),
            cached_read_tokens: self
                .cached_read_tokens
                .saturating_add(other.cached_read_tokens),
            cache_creation_tokens: self
                .cache_creation_tokens
                .saturating_add(other.cache_creation_tokens),
            reasoning_tokens: self.reasoning_tokens.saturating_add(other.reasoning_tokens),
            total_tokens: self.total_tokens.saturating_add(other.total_tokens),
            model_calls: self.model_calls.saturating_add(other.model_calls),
            cost_usd_ticks: merge_cost_ticks(self.cost_usd_ticks, other.cost_usd_ticks),
            cost_is_partial: self.cost_is_partial || other.cost_is_partial,
            usage_is_incomplete: self.usage_is_incomplete || other.usage_is_incomplete,
            turn_count: 0,
            primary_model_id: None,
            model_usage: IndexMap::new(),
        }
    }

    pub fn saturating_sub(&self, other: &Self) -> Self {
        let mut model_usage = IndexMap::new();
        for (model, row) in &self.model_usage {
            let prev = other.model_usage.get(model).cloned().unwrap_or_default();
            let delta = row.saturating_sub_row(&prev);
            if !delta.is_zero() {
                model_usage.insert(model.clone(), delta);
            }
        }
        let mut out = self.saturating_sub_row(other);
        out.primary_model_id = primary_model(&model_usage);
        out.model_usage = model_usage;
        out
    }

    fn saturating_sub_row(&self, other: &Self) -> Self {
        Self {
            input_tokens: self.input_tokens.saturating_sub(other.input_tokens),
            output_tokens: self.output_tokens.saturating_sub(other.output_tokens),
            cached_read_tokens: self
                .cached_read_tokens
                .saturating_sub(other.cached_read_tokens),
            cache_creation_tokens: self
                .cache_creation_tokens
                .saturating_sub(other.cache_creation_tokens),
            reasoning_tokens: self.reasoning_tokens.saturating_sub(other.reasoning_tokens),
            total_tokens: self.total_tokens.saturating_sub(other.total_tokens),
            model_calls: self.model_calls.saturating_sub(other.model_calls),
            cost_usd_ticks: sub_cost_ticks(self.cost_usd_ticks, other.cost_usd_ticks),
            cost_is_partial: self.cost_is_partial || other.cost_is_partial,
            usage_is_incomplete: self.usage_is_incomplete,
            turn_count: 0,
            primary_model_id: None,
            model_usage: IndexMap::new(),
        }
    }

    fn is_zero(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cached_read_tokens == 0
            && self.cache_creation_tokens == 0
            && self.reasoning_tokens == 0
            && self.model_calls == 0
            && self.cost_usd_ticks.is_none()
    }
}

pub enum UsageLoad {
    SessionNotFound,
    NoUsage,
    Ready(Box<SessionUsageFile>),
}

impl SessionUsageFile {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            ..Self::default()
        }
    }

    pub fn load_for_session(session_id: &str) -> std::io::Result<UsageLoad> {
        load_for_session_in_root(session_id, &fuigo_config::sessions_root())
    }

    pub fn turn(&self, turn_number: u32) -> Option<&TurnUsage> {
        self.turns
            .iter()
            .find(|turn| turn.turn_number == turn_number)
    }

    /// Take the oldest rows past [`MAX_TURN_ROWS`] as archive lines (F4). The caller appends them to
    /// [`USAGE_ARCHIVE_FILE`] before it rewrites `usage.json`, so a crash between the two only repeats a line.
    pub fn drain_overflow(&mut self) -> std::io::Result<Vec<u8>> {
        let excess = self.turns.len().saturating_sub(MAX_TURN_ROWS);
        let mut lines = Vec::new();
        for turn in self.turns.drain(..excess) {
            serde_json::to_writer(&mut lines, &turn)?;
            lines.push(b'\n');
        }
        Ok(lines)
    }

    /// Put back the rows `dir`'s [`USAGE_ARCHIVE_FILE`] holds and `usage.json` no longer does, oldest first (F4).
    pub fn merge_archive(&mut self, dir: &std::path::Path) -> std::io::Result<()> {
        let data = match std::fs::read(dir.join(USAGE_ARCHIVE_FILE)) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut archived = std::collections::BTreeMap::new();
        // A torn last line (a crash mid-append) is skipped; its row is still in `usage.json`.
        for turn in data
            .split(|b| *b == b'\n')
            .filter_map(|line| serde_json::from_slice::<TurnUsage>(line).ok())
        {
            archived.insert(turn.turn_number, turn);
        }
        for turn in &self.turns {
            archived.remove(&turn.turn_number);
        }
        if !archived.is_empty() {
            let kept = std::mem::take(&mut self.turns);
            self.turns = archived.into_values().chain(kept).collect();
        }
        Ok(())
    }

    pub fn retain_turns_through(&mut self, max_turn: u32) {
        if self.session.turn_count > self.turns.len() as u64 {
            // Older rows were capped away (F4): their usage lives only in `session`, so subtract the dropped later rows.
            let mut session = self.session.clone();
            let mut dropped = 0;
            for turn in self.turns.iter().filter(|turn| turn.turn_number > max_turn) {
                session = session.saturating_sub(&turn.usage);
                dropped += 1;
            }
            self.turns.retain(|turn| turn.turn_number <= max_turn);
            session.turn_count = self.session.turn_count.saturating_sub(dropped);
            self.session = session;
            return;
        }
        self.turns.retain(|turn| turn.turn_number <= max_turn);
        let mut session = UsageSummary::default();
        for turn in &self.turns {
            session = session.saturating_add(&turn.usage);
        }
        session.turn_count = self.turns.len() as u64;
        session.primary_model_id = primary_model(&session.model_usage);
        self.session = session;
    }

    pub fn apply_turn(
        &mut self,
        turn_number: u32,
        ended_at: impl Into<String>,
        live: &UsageSummary,
        prev_live: Option<&UsageSummary>,
    ) -> u32 {
        let fold_into = (self.last_incoming_turn == Some(turn_number))
            .then_some(self.last_written_turn)
            .flatten();
        let written = self.apply_turn_internal(turn_number, ended_at, live, prev_live, fold_into);
        self.last_incoming_turn = Some(turn_number);
        self.last_written_turn = Some(written);
        written
    }

    pub(crate) fn restore_apply_cursor(
        &mut self,
        last_incoming_turn: Option<u32>,
        last_written_turn: Option<u32>,
    ) {
        self.last_incoming_turn = last_incoming_turn;
        self.last_written_turn = last_written_turn;
    }

    pub(crate) fn apply_cursor(&self) -> (Option<u32>, Option<u32>) {
        (self.last_incoming_turn, self.last_written_turn)
    }

    /// Fold into `fold_into` when this process already persisted the same incoming turn number (late interjection).
    /// Otherwise a colliding inherited row is renumbered.
    fn apply_turn_internal(
        &mut self,
        mut turn_number: u32,
        ended_at: impl Into<String>,
        live: &UsageSummary,
        prev_live: Option<&UsageSummary>,
        fold_into: Option<u32>,
    ) -> u32 {
        let ended_at = ended_at.into();
        self.updated_at = ended_at.clone();

        let mut turn_usage = match prev_live {
            Some(prev) if live.covers(prev) => live.saturating_sub(prev),
            _ => live.clone(),
        };

        if let Some(fold_n) = fold_into
            && let Some(existing) = self
                .turns
                .iter_mut()
                .find(|turn| turn.turn_number == fold_n)
        {
            if turn_usage.is_zero() {
                return fold_n;
            }
            existing.ended_at = ended_at;
            existing.usage = existing.usage.saturating_add(&turn_usage);
            existing.usage.turn_count = 1;
            existing.usage.primary_model_id = primary_model(&existing.usage.model_usage);
            let turn_count = self.session.turn_count.max(self.turns.len() as u64);
            self.session = self.session.saturating_add(&turn_usage);
            self.session.turn_count = turn_count;
            return fold_n;
        }

        if self
            .turns
            .iter()
            .any(|turn| turn.turn_number == turn_number)
        {
            turn_number = self
                .turns
                .iter()
                .map(|turn| turn.turn_number)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
        }

        turn_usage.turn_count = 1;
        turn_usage.primary_model_id = primary_model(&turn_usage.model_usage);

        self.turns.push(TurnUsage {
            turn_number,
            ended_at,
            usage: turn_usage.clone(),
        });

        let turn_count = (self.session.turn_count + 1).max(self.turns.len() as u64);
        self.session = self.session.saturating_add(&turn_usage);
        self.session.turn_count = turn_count;
        self.session.primary_model_id = primary_model(&self.session.model_usage);
        turn_number
    }
}

fn load_for_session_in_root(
    session_id: &str,
    sessions_root: &std::path::Path,
) -> std::io::Result<UsageLoad> {
    let Some(dir) = crate::session::persistence::find_persisted_session_dir_by_id_in_root_result(
        session_id,
        sessions_root,
    )?
    else {
        return Ok(UsageLoad::SessionNotFound);
    };
    let path = dir.join(crate::session::storage::USAGE_FILE);
    if !path.is_file() {
        return Ok(UsageLoad::NoUsage);
    }
    let data = std::fs::read(&path)?;
    if data.iter().all(u8::is_ascii_whitespace) || fuigo_secrets::at_rest::is_withheld(&data) {
        return Ok(UsageLoad::NoUsage);
    }
    let mut file: SessionUsageFile = serde_json::from_slice(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.merge_archive(&dir)?;
    Ok(UsageLoad::Ready(Box::new(file)))
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

fn primary_model(model_usage: &IndexMap<String, UsageSummary>) -> Option<String> {
    model_usage
        .iter()
        .max_by_key(|(_, row)| (row.model_calls, row.total_tokens))
        .map(|(name, _)| name.clone())
}

fn merge_cost_ticks(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (None, None) => None,
        (a, b) => reported_cost_ticks(Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0)))),
    }
}

fn sub_cost_ticks(live: Option<i64>, previous: Option<i64>) -> Option<i64> {
    match (live, previous) {
        (None, _) => None,
        (Some(live), None) => reported_cost_ticks(Some(live)),
        (Some(live), Some(previous)) => reported_cost_ticks(Some(live.saturating_sub(previous))),
    }
}

#[cfg(test)]
#[path = "usage_file_tests.rs"]
mod tests;
