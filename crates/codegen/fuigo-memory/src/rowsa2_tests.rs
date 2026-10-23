//! ROWS-A2 (1.0.32) memory rows: 50.14 CJK search, 54.6 `/memory` skips symlinked notes.

use crate::index::MemoryIndex;
use fuigo_config_types::MemoryIndexConfig;
use crate::storage::MemoryStorage;
use tempfile::TempDir;

fn storage(tmp: &TempDir) -> MemoryStorage {
    let global = tmp.path().join("memory");
    let workspace = global.join("test_ws");
    std::fs::create_dir_all(&workspace).unwrap();
    MemoryStorage::with_paths(global, workspace)
}

fn open(tmp: &TempDir) -> MemoryIndex {
    MemoryIndex::open_or_create(&tmp.path().join("test.sqlite"), storage(tmp), MemoryIndexConfig::default(), 8).unwrap()
}

fn note(tmp: &TempDir, name: &str, text: &str) -> std::path::PathBuf {
    let path = tmp.path().join("memory/test_ws").join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

fn hits(idx: &MemoryIndex, query: &str) -> usize {
    idx.search_fts(query, 10).unwrap().iter().filter(|r| r.confidence > 0.0).count()
}

#[test]
fn a_cjk_query_finds_the_note_that_holds_it() {
    let tmp = TempDir::new().unwrap();
    let mut idx = open(&tmp);
    let path = note(&tmp, "notes.md", "# 会议记录\n\n我们讨论了数据库迁移的方案，决定下周开始。\n");
    idx.reindex_file(&path, "workspace").unwrap();
    for query in ["数据库", "数据库迁移", "迁移方案", "会议记录"] {
        assert_eq!(hits(&idx, query), 1, "query {query:?} must find the note");
    }
    assert_eq!(hits(&idx, "天气预报"), 0, "text that is not in the note must not match");
}

#[test]
fn japanese_and_korean_text_is_searchable_too() {
    let tmp = TempDir::new().unwrap();
    let mut idx = open(&tmp);
    let path = note(&tmp, "ja.md", "データベースの移行について話し合いました。\n\n데이터베이스 마이그레이션 계획\n");
    idx.reindex_file(&path, "workspace").unwrap();
    assert_eq!(hits(&idx, "移行"), 1);
    assert_eq!(hits(&idx, "マイグレ"), 0, "an absent kana run must not match");
    assert_eq!(hits(&idx, "마이그레이션"), 1);
}

#[test]
fn mixed_text_is_found_by_its_latin_words_and_its_cjk_words() {
    let tmp = TempDir::new().unwrap();
    let mut idx = open(&tmp);
    let path = note(&tmp, "mixed.md", "Planning the 数据库 migration with the platform team.\n");
    idx.reindex_file(&path, "workspace").unwrap();
    assert_eq!(hits(&idx, "migration"), 1);
    assert_eq!(hits(&idx, "数据库"), 1);
}

#[test]
fn editing_and_deleting_a_cjk_note_leaves_no_stale_match() {
    let tmp = TempDir::new().unwrap();
    let mut idx = open(&tmp);
    let path = note(&tmp, "edit.md", "旧的部署流程说明。\n");
    idx.reindex_file(&path, "workspace").unwrap();
    assert_eq!(hits(&idx, "部署流程"), 1);

    std::fs::write(&path, "新的发布清单说明。\n").unwrap();
    idx.reindex_file(&path, "workspace").unwrap();
    assert_eq!(hits(&idx, "部署流程"), 0, "the replaced text must be gone from the index");
    assert_eq!(hits(&idx, "发布清单"), 1);

    idx.delete_path(&path).unwrap();
    assert_eq!(hits(&idx, "发布清单"), 0);
}

/// An index written before CJK search was added holds each note's raw text. Opening it must make those notes searchable
/// without a manual rebuild, and a later edit must still remove the right entry.
#[test]
fn an_index_built_before_cjk_search_is_migrated_on_open() {
    let tmp = TempDir::new().unwrap();
    let path = note(&tmp, "old.md", "旧版本索引里的数据库笔记。\n");
    {
        let mut idx = open(&tmp);
        idx.reindex_file(&path, "workspace").unwrap();
        let db = idx.db();
        db.execute_batch(
            "DROP TABLE chunks_fts;
             CREATE VIRTUAL TABLE chunks_fts USING fts5(text, content='');
             INSERT INTO chunks_fts(rowid, text) SELECT rowid, text FROM chunks;
             DELETE FROM meta WHERE key = 'fts_cjk_v';",
        )
        .unwrap();
    }
    let mut idx = open(&tmp);
    assert_eq!(hits(&idx, "数据库"), 1, "a note indexed before the change must be found after it");
    std::fs::write(&path, "改写后的内容。\n").unwrap();
    idx.reindex_file(&path, "workspace").unwrap();
    assert_eq!(hits(&idx, "数据库"), 0, "the old entry must be removed by the edit");
    assert_eq!(hits(&idx, "改写后"), 1);
}

#[cfg(unix)]
#[test]
fn a_symlinked_note_is_not_listed() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new().unwrap();
    let storage = storage(&tmp);
    let sessions = storage.sessions_dir();
    std::fs::create_dir_all(&sessions).unwrap();
    let real = sessions.join("2026-01-01-real.md");
    std::fs::write(&real, "a real note\n").unwrap();
    // A link to a note that lives inside the workspace: `allows_path` resolves it, so only the link itself gives it away.
    symlink(&real, sessions.join("2026-01-02-link.md")).unwrap();
    // A link standing in for MEMORY.md.
    symlink(&real, storage.workspace_memory_file()).unwrap();

    let listed = storage.list_memory_files().unwrap();
    let names: Vec<String> = listed.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
    assert_eq!(names, vec!["2026-01-01-real.md".to_string()], "only the real note may be listed: {names:?}");
}
