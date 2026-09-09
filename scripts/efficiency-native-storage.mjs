// Generate a dependency-free native observation harness from the CURRENT storage
// primitives. This tests native file behavior, not the complete shell or power loss.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
const sourcePath = resolve('crates/codegen/fuigo-shell/src/session/storage/mod.rs');
const source = readFileSync(sourcePath, 'utf8');
const begin = source.indexOf('pub(crate) fn write_bytes_atomic(');
const end = source.indexOf('/// Run `create`', begin);
if (begin < 0 || end <= begin) throw new Error('storage extraction anchors changed');
const primitives = source.slice(begin, end);
const digest = createHash('sha256').update(primitives).digest('hex');
const output = process.argv[2];
if (!output) throw new Error('pass an explicit test-owned output .rs path');
writeFileSync(output, `// Source primitive SHA256: ${digest}
use std::{io::{self, Write}, path::{Path, PathBuf}, sync::atomic::{AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
// Only temp-name minting is fixture-local; the production write/sync/rename
// functions below are copied byte-for-byte from the current candidate.
fn temp_sibling(path: &Path) -> PathBuf {
    path.with_extension(format!("tmp-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)))
}
${primitives}
fn fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fuigo-storage-observation-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir(&dir).unwrap(); dir
}
#[test]
fn native_create_replace_and_reopen() {
    let dir = fixture(); let path = dir.join("checkpoint.json");
    write_bytes_atomic(&path, b"old").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    write_bytes_atomic(&path, b"new").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn failed_file_sync_preserves_old_content() {
    let dir = fixture(); let path = dir.join("checkpoint.json");
    write_bytes_atomic(&path, b"old").unwrap();
    assert!(write_bytes_atomic_with(&path, b"new", |_| Err(io::Error::other("fixture sync fault")), || Ok(())).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn post_rename_directory_failure_is_reported_and_retryable() {
    let dir = fixture(); let path = dir.join("checkpoint.json");
    assert!(write_bytes_atomic_with(&path, b"new", sync_file_durable, || Err(io::Error::other("fixture directory fault"))).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"new");
    write_bytes_atomic(&path, b"confirmed").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"confirmed");
    std::fs::remove_dir_all(dir).unwrap();
}
`);
console.log(JSON.stringify({ sourcePath, primitiveSha256: digest, output, limitation: 'Native syscall observations; not full product or power-loss qualification. Windows directory sync remains the existing no-op.' }));
