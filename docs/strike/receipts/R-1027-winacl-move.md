# R-1027 b27-1a WINACL-MOVE

Pure code move, no rule/constant/message change. Base 8a04062f.

## Destination: new crate `crates/codegen/fuigo-win-acl`
None of `fuigo-file-utils` (heavy: aws, reqwest, tokio), `fuigo-paths` (UTF-8 path types), `fuigo-dirs` (home dirs), `fuigo-tty-utils`
(process spawning) is about Windows security; a new crate with only `windows` as a cfg(windows) dependency has no cycle risk for
`fuigo-shell` or `fuigo-mcp`. Added to workspace members and `[workspace.dependencies]`; `fuigo-shell` depends on it.

## What moved
- `policy.rs` (every OS): from `peer_inbox/win_policy.rs`: `AceSummary`, `DaclSummary`, `RawAce`, `dacl_summary_from_binary`,
  `is_sid_text`, `SID_SYSTEM`, `SID_ADMINISTRATORS`, `locator_owner_ok`, `locator_dacl_ok`, tests `owner_rule`, `dacl_rule`,
  `sid_text_check`. `win_policy.rs` re-exports them under the same names.
- `sys.rs` (cfg windows): from `leader/peer_auth.rs`: `code`, `Owned`, `sid_to_string`, `token_info_buf`, `token_user_sid`,
  `process_token_user_sid` (was private, now pub), `own_sid` (re-exported by `peer_auth::win`); from `peer_inbox/win_pipe.rs`:
  `owner_and_dacl`, `read_owner_dacl` (the bounded ACE reader; `win_pipe::sys` and `win_dirs` re-import it: one copy);
  from `peer_inbox/win_locator.rs`: `token_elevated`, the cached `our_sid`, and the body of `check_handle`.
- Not moved: directory rules, ancestors, pipe rules, `PipeSecurity`, `bearer_token_file.rs` (untouched).

## Public API (`fuigo_win_acl`)
```rust
pub fn check_owner_only_file(h: &impl AsRawHandle) -> Result<u64 /*size*/, FileAclRefusal>;
pub fn check_owner_only_file_capped(h: &impl AsRawHandle, cap: Option<u64>) -> Result<u64, FileAclRefusal>;
pub enum FileAclRefusal { Io(i32), ReparsePoint, NotRegular, MultipleLinks, TooLarge, WrongOwner, OtherPrincipals }
```
Handle must be opened with `FILE_FLAG_OPEN_REPARSE_POINT`. `Io` = file info, own SID, or security info unreadable/odd shape.
`OtherPrincipals` = NULL DACL or an ACE that is not a plain allow for us/SYSTEM/Administrators.
The peer locator's `check_handle` now calls `check_owner_only_file_capped` (cap kept so the check order is unchanged) and maps:
Io(c)->Io(c), ReparsePoint->Rejected(Symlink), NotRegular->NotRegular, MultipleLinks->HardLinked, TooLarge->TooLarge,
WrongOwner->WrongOwner, OtherPrincipals->WrongMode (identical to the old inline code).

## Non-mechanical changes
1. `fuigo-win-acl/src/sys.rs`: new enum `FileAclRefusal`, new `check_owner_only_file[_capped]` = old `check_handle` body with
   `Disabled::..` replaced by the enum variants (same order: info, reparse, not-regular, links, cap, SID, owner/DACL, owner, DACL).
2. `win_locator.rs`: `check_handle` is now the mapping above; `our_sid()` wraps `fuigo_win_acl::our_sid` mapping `c -> Disabled::Io(c as i32)`;
   imports pruned; test module imports `owner_and_dacl` explicitly.
3. Items made `pub` (were `pub(crate)`), four-space dedent of items lifted out of inline modules, imports pruned; `#[allow(unused_imports)]` on
   the `win_policy` re-export (locator fns are used on Windows only).
4. Cargo.toml / Cargo.lock entries for the new crate.

## Results
- Linux (Hetzner lane b27-1a): `-p fuigo-win-acl` 3 passed; `fuigo-shell --lib peer_inbox` 162 passed, 0 failed.
  `cargo clippy --locked -p fuigo-win-acl -p fuigo-shell --all-targets`: no warnings in touched files (pre-existing ones elsewhere).
- Windows: `check --locked -p fuigo-win-acl -p fuigo-shell -p fuigo-mcp --lib --tests` exit 0 (no warnings in touched files);
  `nextest -p fuigo-win-acl -p fuigo-shell --lib -- peer_inbox --skip pipe_tests` 108 passed, 0 failed; `nextest -p fuigo-win-acl --lib` 3 passed.
  This includes the Windows-only locator tests (owner/DACL/hard link/symlink rejection) that exercise the moved checker.

## Not verified
- Clippy on the Windows target (only `cargo check` there). No pipe tests run (rule). `fuigo-mcp` does not yet depend on the crate (next packet).
