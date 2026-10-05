# P120 Astra audit brief (read-only; no cargo, no builds)

Repository: this worktree (strike/p120, parent 9381f19c6a67477ce7ff9623943912ed74017d59). Review `git diff 9381f19c..HEAD`.

Backlog items (release-notes-1.0.21 post-release backlog, known limit K16; source: R113 Round 3 and R3.5, in
/Volumes/Mando/WaylandBots/Fuigo/strike-integration/docs/strike/receipts/R113-p113.md):
1. Archive scrub on joined records. A `/feedback` archive (crates/codegen/fuigo-shell/src/upload/feedback_archive.rs, with
   fuigo-secrets `sanitizer.rs`: `PrivateKeyJoin`, `opens_private_key_block`, the PEM regexes) must catch a private key split
   across several strings of a record or several session records (envelope strings between chunks, chunks shorter than a
   base64 line), a torn key body followed on its line by terminal colour codes, and must not redact a long base64-looking
   string after a marker that opens no key (ordinary text after it).
2. Remaining env-inheriting children: git (hooks), direnv/.envrc, external sign-in/identity commands (`shell_c`), pager
   programs ($EDITOR, $PAGER, status-line command, notification hooks, `fuigo wrap`) must not inherit Fuigo's secrets, using the
   same filter as the other spawn sites (`fuigo_secrets::child_env`, removed BEFORE explicit variables).
3. Session files 0600: created owner-only and tightened when opened for writing (`session/storage/owner_only.rs`); Windows
   equivalent is the owner-only ACL via secure_file::ensure_owner_only_permissions.

For each item answer FIXED or NOT FIXED. List NEW regressions compared with 9381f19c and with v1.0.20. Rate each finding
BLOCKER / HIGH / MEDIUM / LOW. LAND-OK needs zero BLOCKER and zero HIGH. Check especially: a key shape that still leaks, a
benign string that is now redacted, a spawn site that still inherits secrets or that loses an explicit variable, a session
file creation path that still uses the default mode, behaviour changes for git credential helpers.
