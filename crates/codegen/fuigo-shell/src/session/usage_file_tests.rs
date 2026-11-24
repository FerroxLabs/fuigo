use super::*;
use fuigo_chat_state::UsageLedger;
use fuigo_sampling_types::TokenUsage;

fn tu(prompt: u32, completion: u32) -> TokenUsage {
    TokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        total_tokens: prompt + completion,
        reasoning_tokens: 0,
        cached_prompt_tokens: 0,
        cache_creation_prompt_tokens: 0,
    }
}

fn live(calls: &[(&str, u32, u32, Option<i64>)]) -> UsageSummary {
    let mut ledger = UsageLedger::default();
    for (model, prompt, completion, cost) in calls {
        ledger.record_main_loop_call(model, &tu(*prompt, *completion), Some(10), *cost);
    }
    UsageSummary::from_ledger(&ledger)
}

#[test]
fn first_turn_writes_session_and_one_turn() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "2026-08-26T00:00:00Z", &first, None);

    assert_eq!(file.turns.len(), 1);
    assert_eq!(file.turns[0].turn_number, 1);
    assert_eq!(file.turns[0].usage.input_tokens, 100);
    assert_eq!(file.turns[0].usage.output_tokens, 20);
    assert_eq!(file.turns[0].usage.cost_usd_ticks, Some(50));
    assert_eq!(file.session.input_tokens, 100);
    assert_eq!(file.session.output_tokens, 20);
    assert_eq!(file.session.turn_count, 1);
    assert_eq!(file.session.cost_usd_ticks, Some(50));
    assert_eq!(file.session.primary_model_id.as_deref(), Some("grok-4"));
    assert_eq!(file.updated_at, "2026-08-26T00:00:00Z");
}

#[test]
fn session_primary_model_is_the_most_used_not_the_last_turn() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 80, 10, Some(40))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(
        2,
        "t2",
        &live(&[
            ("grok-4", 100, 20, Some(50)),
            ("grok-4", 80, 10, Some(40)),
            ("fuigo-fast", 10, 2, Some(1)),
        ]),
        Some(&first),
    );

    assert_eq!(
        file.turns[1].usage.primary_model_id.as_deref(),
        Some("fuigo-fast")
    );
    assert_eq!(file.session.primary_model_id.as_deref(), Some("grok-4"));
}

#[test]
fn second_turn_appends_and_session_becomes_latest_ledger() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(
        2,
        "t2",
        &live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 40, 10, Some(20))]),
        Some(&first),
    );

    assert_eq!(file.turns.len(), 2);
    assert_eq!(file.turns[1].turn_number, 2);
    assert_eq!(file.turns[1].usage.input_tokens, 40);
    assert_eq!(file.turns[1].usage.output_tokens, 10);
    assert_eq!(file.turns[1].usage.cost_usd_ticks, Some(20));
    assert_eq!(file.session.input_tokens, 140);
    assert_eq!(file.session.output_tokens, 30);
    assert_eq!(file.session.turn_count, 2);
    assert_eq!(file.session.cost_usd_ticks, Some(70));
}

#[test]
fn inherited_turn_number_without_fold_appends() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.restore_apply_cursor(None, None);
    let resumed = live(&[("grok-4", 10, 2, Some(5))]);
    file.apply_turn(1, "t-resume", &resumed, None);

    assert_eq!(file.turns.len(), 2);
    assert_eq!(file.turns[0].turn_number, 1);
    assert_eq!(file.turns[0].usage.input_tokens, 100);
    assert_eq!(file.turns[1].turn_number, 2);
    assert_eq!(file.turns[1].usage.input_tokens, 10);
    assert_eq!(file.session.input_tokens, 110);
    assert_eq!(file.session.turn_count, 2);
}

#[test]
fn duplicate_turn_number_zero_delta_does_not_mutate_turns() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(1, "t1-again", &first, Some(&first));

    assert_eq!(file.turns.len(), 1);
    assert_eq!(file.turns[0].ended_at, "t1");
    assert_eq!(file.session.turn_count, 1);
    assert_eq!(file.updated_at, "t1-again");
}

#[test]
fn duplicate_turn_number_folds_extra_live_usage() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    let continued = live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 40, 10, Some(20))]);
    file.apply_turn(1, "t1-late", &continued, Some(&first));

    assert_eq!(file.turns.len(), 1);
    assert_eq!(file.turns[0].ended_at, "t1-late");
    assert_eq!(file.turns[0].usage.input_tokens, 140);
    assert_eq!(file.turns[0].usage.output_tokens, 30);
    assert_eq!(file.turns[0].usage.cost_usd_ticks, Some(70));
    assert_eq!(file.session.input_tokens, 140);
    assert_eq!(file.session.output_tokens, 30);
    assert_eq!(file.session.turn_count, 1);
    assert_eq!(file.session.cost_usd_ticks, Some(70));
}

#[test]
fn resume_folds_new_process_ledger_onto_persisted_session() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(
        2,
        "t2",
        &live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 40, 10, Some(20))]),
        Some(&first),
    );

    let post_resume_1 = live(&[("grok-4", 25, 5, Some(8))]);
    file.apply_turn(3, "t3", &post_resume_1, None);

    assert_eq!(file.turns.len(), 3);
    assert_eq!(file.turns[2].turn_number, 3);
    assert_eq!(file.turns[2].usage.input_tokens, 25);
    assert_eq!(file.turns[2].usage.output_tokens, 5);
    assert_eq!(file.session.input_tokens, 165);
    assert_eq!(file.session.output_tokens, 35);
    assert_eq!(file.session.turn_count, 3);
    assert_eq!(file.session.cost_usd_ticks, Some(78));
}

#[test]
fn resume_later_turns_use_process_local_delta() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(
        2,
        "t2",
        &live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 40, 10, Some(20))]),
        Some(&first),
    );

    let post_resume_1 = live(&[("grok-4", 25, 5, Some(8))]);
    file.apply_turn(3, "t3", &post_resume_1, None);
    file.apply_turn(
        4,
        "t4",
        &live(&[("grok-4", 25, 5, Some(8)), ("grok-4", 30, 6, Some(9))]),
        Some(&post_resume_1),
    );

    assert_eq!(file.turns.len(), 4);
    assert_eq!(file.turns[3].usage.input_tokens, 30);
    assert_eq!(file.turns[3].usage.output_tokens, 6);
    assert_eq!(file.session.input_tokens, 195);
    assert_eq!(file.session.output_tokens, 41);
    assert_eq!(file.session.turn_count, 4);
    assert_eq!(file.session.cost_usd_ticks, Some(87));
}

#[test]
fn retain_turns_through_drops_later_turns_and_rebuilds_session() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(
        2,
        "t2",
        &live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 40, 10, Some(20))]),
        Some(&first),
    );
    file.retain_turns_through(1);

    assert_eq!(file.turns.len(), 1);
    assert_eq!(file.turns[0].turn_number, 1);
    assert_eq!(file.session.input_tokens, 100);
    assert_eq!(file.session.turn_count, 1);
    assert_eq!(file.session.cost_usd_ticks, Some(50));
}

#[test]
fn turn_lookup_returns_matching_row() {
    let mut file = SessionUsageFile::new("sess-1");
    let first = live(&[("grok-4", 100, 20, Some(50))]);
    file.apply_turn(1, "t1", &first, None);
    file.apply_turn(
        2,
        "t2",
        &live(&[("grok-4", 100, 20, Some(50)), ("grok-4", 40, 10, Some(20))]),
        Some(&first),
    );

    assert_eq!(file.turn(2).unwrap().usage.input_tokens, 40);
    assert!(file.turn(3).is_none());
}

#[test]
fn covers_detects_same_process_vs_reset_ledger() {
    let bigger = live(&[("m", 10, 1, None), ("m", 5, 1, None)]);
    let smaller = live(&[("m", 5, 1, None)]);
    assert!(bigger.covers(&smaller));
    assert!(!smaller.covers(&bigger));
    assert!(smaller.covers(&UsageSummary::default()));
}

#[test]
fn turn_rows_are_capped_and_session_totals_keep_every_turn() {
    let mut file = SessionUsageFile::new("sess-1");
    let turns = MAX_TURN_ROWS as u32 + 50;
    for n in 1..=turns {
        file.apply_turn(
            n,
            format!("t{n}"),
            &live(&[("grok-4", 10, 2, Some(1))]),
            None,
        );
        file.drain_overflow().unwrap();
    }
    let before = serde_json::to_vec_pretty(&file).unwrap().len();
    assert_eq!(file.turns.len(), MAX_TURN_ROWS);
    assert_eq!(file.turns[0].turn_number, 51);
    assert_eq!(file.session.turn_count, u64::from(turns));
    assert_eq!(file.session.input_tokens, 10 * u64::from(turns));
    assert_eq!(file.session.cost_usd_ticks, Some(i64::from(turns)));
    // Size stays flat: another 1,000 turns do not grow the rewrite.
    for n in turns + 1..=turns + 1_000 {
        file.apply_turn(
            n,
            format!("t{n}"),
            &live(&[("grok-4", 10, 2, Some(1))]),
            None,
        );
        file.drain_overflow().unwrap();
    }
    let after = serde_json::to_vec_pretty(&file).unwrap().len();
    assert!(
        after < before + before / 100, // only wider numbers, never another row
        "usage.json grew from {before} to {after} bytes"
    );
    assert_eq!(file.session.turn_count, u64::from(turns) + 1_000);

    // A fork at a turn still inside the kept rows keeps the totals of every turn up to it.
    file.retain_turns_through(turns + 900);
    assert_eq!(file.turns.len(), MAX_TURN_ROWS - 100);
    assert_eq!(file.session.turn_count, u64::from(turns) + 900);
    assert_eq!(file.session.input_tokens, 10 * (u64::from(turns) + 900));
    assert_eq!(file.session.cost_usd_ticks, Some(i64::from(turns) + 900));
}

/// F4: rows past the cap move to `usage_turns.jsonl` instead of being dropped. A legacy 500-row `usage.json` keeps every
/// row on its first turn here, and `fuigo usage <id> N` still finds a turn older than the last 200.
#[tokio::test]
async fn capped_rows_are_archived_and_still_readable() {
    use crate::session::info::Info;
    use crate::session::storage::StorageAdapter;
    use crate::session::storage::jsonl::JsonlStorageAdapter;
    use agent_client_protocol as acp;

    let tmp = tempfile::TempDir::new().unwrap();
    let adapter = JsonlStorageAdapter::with_root(tmp.path().to_path_buf());
    let info = Info {
        id: acp::SessionId::new("usage-archive"),
        cwd: "/usage".to_string(),
    };
    adapter
        .init_session(&info, crate::session::persistence::default_model_id())
        .await
        .unwrap();
    let one = || live(&[("grok-4", 10, 2, Some(1))]);
    let mut legacy = SessionUsageFile::new("usage-archive");
    for n in 1..=500 {
        legacy.apply_turn(n, format!("t{n}"), &one(), None);
    }
    assert_eq!(legacy.turns.len(), 500);
    adapter.write_usage(&info, &legacy).await.unwrap();

    adapter
        .update_usage(
            &info,
            Box::new(move |file| {
                let mut file = file.unwrap();
                file.apply_turn(501, "t501", &one(), None);
                file
            }),
        )
        .await
        .unwrap();
    let on_disk = adapter.read_usage(&info).await.unwrap().unwrap();
    assert_eq!(
        on_disk.turns.len(),
        MAX_TURN_ROWS,
        "usage.json stays capped"
    );
    assert_eq!(on_disk.turns[0].turn_number, 302);

    let UsageLoad::Ready(file) =
        load_for_session_in_root("usage-archive", &fuigo_config::sessions_root_in(tmp.path()))
            .unwrap()
    else {
        panic!("usage not found");
    };
    assert_eq!(file.turns.len(), 501, "every row survives the migration");
    assert!(file.turns.iter().map(|t| t.turn_number).eq(1..=501));
    let old = file
        .turn(1)
        .expect("turn 1, older than the last 200, is still readable");
    assert_eq!(old.usage.input_tokens, 10);
    assert_eq!(file.session.turn_count, 501);
    assert_eq!(file.session.input_tokens, 10 * 501);
}

/// F4: a crash between the archive append and the `usage.json` rewrite repeats archive lines on the next turn. Each turn
/// is read once: the `usage.json` row wins, else the last archive line; a torn last line is skipped.
#[test]
#[allow(
    clippy::disallowed_methods,
    reason = "test fixture: writes a crash-shaped usage_turns.jsonl into a test-owned temp dir; no session writer runs there"
)]
fn crash_duplicated_archive_lines_are_read_once() {
    let tmp = tempfile::TempDir::new().unwrap();
    let one = || live(&[("grok-4", 10, 2, Some(1))]);
    let mut file = SessionUsageFile::new("dup");
    for n in 1..=210 {
        file.apply_turn(n, format!("t{n}"), &one(), None);
    }
    let first = file.drain_overflow().unwrap();
    // The crash: rows 1..=10 were appended, `usage.json` was not rewritten, so the next turn drains them again.
    let mut archive = first.clone();
    archive.extend_from_slice(&first);
    // A stale archive line for a row `usage.json` still holds, with different numbers: the `usage.json` row wins.
    let mut stale = file.turns[0].clone();
    stale.usage.input_tokens = 999;
    serde_json::to_writer(&mut archive, &stale).unwrap();
    archive.push(b'\n');
    archive.extend_from_slice(br#"{"turnNumber":5,"inputTo"#);
    std::fs::write(tmp.path().join(USAGE_ARCHIVE_FILE), &archive).unwrap();

    file.merge_archive(tmp.path()).unwrap();
    assert_eq!(file.turns.len(), 210, "every turn once");
    assert!(file.turns.iter().map(|t| t.turn_number).eq(1..=210));
    assert_eq!(file.turn(11).unwrap().usage.input_tokens, 10);
    assert!(file.turns.iter().all(|t| t.usage.input_tokens == 10));
}
