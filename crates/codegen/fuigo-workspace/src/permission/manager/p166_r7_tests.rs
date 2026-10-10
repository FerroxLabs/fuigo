//! P166 round 7 (Grok r6 re-audit): the protected-write floor closes the CLASS, not seven more programs.
//!
//! Every row is `(command, blocked)`: `blocked` means the protected floor must fire for the command, `false` means it
//! must stay silent (a read of a protected file, an ordinary write, a routine git verb). Rows are table-driven so the
//! receipt's sweep table maps one row to one test case.

use super::{PermissionState, bash_protected_write_target, evaluate_bash};

fn floor_in(cwd: &std::path::Path, cmd: &str) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    let state = PermissionState::default();
    let evaluation = evaluate_bash(cmd, &state, true);
    bash_protected_write_target(&evaluation, cwd, None)
}

fn check(rows: &[(&str, bool)]) {
    let project = tempfile::tempdir().unwrap();
    let cwd = project.path();
    std::fs::create_dir_all(cwd.join("out")).unwrap();
    std::fs::create_dir_all(cwd.join("src")).unwrap();
    let mut wrong = Vec::new();
    for (cmd, blocked) in rows {
        let got = floor_in(cwd, cmd);
        if got.is_some() != *blocked {
            wrong.push(format!("{cmd}: expected blocked={blocked}, got {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "protected floor mismatches:\n{}", wrong.join("\n"));
}

/// HIGH 1: every non-read `git config` writes the file it selects; `core.hooksPath` fails closed on every route.
#[test]
fn p166_r7_git_config_and_hooks_path() {
    check(&[
        ("git config core.hooksPath /tmp/evil-hooks", true),
        ("git config CORE.HOOKSPATH /tmp/evil-hooks", true),
        ("git config --global core.hooksPath /tmp/evil-hooks", true),
        ("git config --worktree core.hooksPath /tmp/evil-hooks", true),
        ("git config --system user.name x", true),
        ("git config set core.hooksPath /tmp/evil-hooks", true),
        ("git config set --system user.name x", true),
        ("git config --add core.hooksPath /tmp/evil-hooks", true),
        ("git config --replace-all core.hooksPath /tmp/evil-hooks", true),
        ("git config --unset core.hooksPath", false),
        ("git config unset core.hooksPath", false),
        ("git config --edit", true),
        ("git config edit", true),
        ("git config include.path /tmp/evil.cfg", true),
        ("git config --file .mcp.json a.b c", true),
        ("git -c core.hooksPath=/tmp/evil-hooks commit -m x", true),
        ("git -c CORE.hookspath=/tmp/evil-hooks status", true),
        ("git --config-env=core.hooksPath=EVIL status", true),
        ("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/tmp/e git commit -m x", true),
        ("env GIT_CONFIG_KEY_0=core.hooksPath git status", true),
        ("export GIT_CONFIG_KEY_0=core.hooksPath", true),
        // Reads and ordinary config writes stay silent.
        ("git config --get core.hooksPath", false),
        ("git config core.hooksPath", false),
        ("git config get core.hooksPath", false),
        ("git config --list", false),
        ("git config list", false),
        ("git config user.name x", false),
        ("git config --global user.name x", false),
        ("git config --unset user.name", false),
        ("git -c user.name=x commit -m x", false),
    ]);
}

/// HIGH 2: `ffmpeg`/`convert` write an output that is not the last word.
#[test]
fn p166_r7_media_outputs_anywhere() {
    check(&[
        ("ffmpeg -i in.mp4 .git/hooks/pre-commit -y", true),
        ("ffmpeg -y -i in.mp4 .mcp.json -loglevel error", true),
        ("convert in.png .mcp.json -quality 80", true),
        ("convert in.png -write .mcp.json out.png", true),
        ("magick in.png .mcp.json -quality 80", true),
        ("ffmpeg -i a.mp4 out/b.mp4", false),
        ("convert a.png b.png", false),
    ]);
}

/// HIGH 3: editor ex commands and script options.
#[test]
fn p166_r7_editor_ex_commands() {
    check(&[
        ("vim -c 'w! .git/hooks/pre-commit' README.md", true),
        ("vim --cmd 'w .mcp.json' README.md", true),
        ("vim '+w .mcp.json' README.md", true),
        ("nvim -c 'wq .mcp.json' README.md", true),
        ("vi -c 'w .mcp.json' README.md", true),
        ("ex -c 'w .mcp.json' README.md", true),
        ("emacs --eval '(write-file \".mcp.json\")' README.md", true),
        ("emacs --batch --eval '(write-region 1 2 \".git/hooks/pre-commit\")' README.md", true),
        ("vim README.md", false),
        ("vim -c 'set nu' README.md", false),
    ]);
}

/// MEDIUM 4: a dashed `ar` mode word means the archive is the first file operand.
#[test]
fn p166_r7_ar_dashed_mode() {
    check(&[
        ("ar -r .git/hooks/pre-commit hook.o", true),
        ("ar -rcs .mcp.json a.o", true),
        ("ar rcs .mcp.json a.o", true),
        ("ar -t lib.a", false),
        ("ar -r out/lib.a a.o", false),
    ]);
}

/// MEDIUM 5: `rsync` log and batch files are written files.
#[test]
fn p166_r7_rsync_log_and_batch() {
    check(&[
        ("rsync -a src/ /tmp/out --log-file=.git/hooks/pre-commit", true),
        ("rsync -a src/ /tmp/out --log-file .mcp.json", true),
        ("rsync -a src/ /tmp/out --write-batch=.mcp.json", true),
        ("rsync -a src/ /tmp/out --only-write-batch=.mcp.json", true),
        ("rsync -a src/ /tmp/out --log-file=out/log", false),
        ("rsync -a src/ dst/", false),
    ]);
}

/// MEDIUM 6 (false positive): a branch switch, pull or stash pop uses the ordinary FileWrite floor, not the protected
/// one; literal pathspecs naming protected targets stay protected.
#[test]
fn p166_r7_routine_git_is_not_protected_floor() {
    check(&[
        ("git checkout main", false),
        ("git switch main", false),
        ("git pull", false),
        ("git pull origin main", false),
        ("git stash pop", false),
        ("git checkout .mcp.json", true),
        ("git checkout main .mcp.json", true),
        ("git checkout main -- .mcp.json", true),
        ("git checkout -- .git/hooks/pre-commit", true),
        ("git restore .mcp.json", true),
        ("git checkout -- .", true),
        ("git reset --hard", true),
        ("git merge main", true),
        ("git stash apply", true),
    ]);
}

/// LOW 7 plus the class tripwire: a literal protected target anywhere in a non-reader command's words.
#[test]
fn p166_r7_interpreter_one_liners_and_tripwire() {
    check(&[
        ("python3 -c \"open('.mcp.json','w').write('x')\"", true),
        ("python -c \"open('.git/hooks/pre-commit','w')\"", true),
        ("node -e \"require('fs').writeFileSync('.mcp.json','x')\"", true),
        ("perl -e 'open F, \">.mcp.json\"'", true),
        ("ruby -e 'File.write(\".mcp.json\", \"x\")'", true),
        ("php -r 'file_put_contents(\".mcp.json\", \"x\");'", true),
        ("lua -e 'io.open(\".mcp.json\", \"w\")'", true),
        ("deno eval 'Deno.writeTextFileSync(\".mcp.json\", \"\")'", true),
        ("python3 -c \"open('~/.bashrc','w')\"", true),
        ("python3 -c \"open('$HOME/.bashrc','w')\"", true),
        ("python3 -c \"open('./out/../.mcp.json','w')\"", true),
        ("cd .git/hooks && python3 -c \"open('pre-commit','w')\"", true),
        ("some-unknown-tool --out=.mcp.json", true),
        ("some-unknown-tool -o.mcp.json", true),
        ("sh -c 'echo x > .mcp.json'", true),
        // Reads, ordinary commands, and the documented limits stay silent.
        ("python3 -c 'print(1)'", false),
        ("python3 script.py", false),
        ("node build.js", false),
        ("python3 -c \"open('.m'+'cp.json','w')\"", false),
    ]);
}

/// The reader allowlist: reading a protected file never prompts; a reader's output option still does.
#[test]
fn p166_r7_reader_allowlist() {
    check(&[
        ("cat ~/.bashrc", false),
        ("cat .mcp.json", false),
        ("grep -r hooks .git/hooks", false),
        ("ls -la .git/hooks", false),
        ("sed -n 1,5p .mcp.json", false),
        ("head -n 3 .mcp.json", false),
        ("jq . .mcp.json", false),
        ("diff .mcp.json other.json", false),
        ("sha256sum .git/hooks/pre-commit", false),
        ("git diff .mcp.json", false),
        ("git log -p -- .mcp.json", false),
        ("git add .mcp.json", false),
        ("git commit -m 'update .mcp.json'", false),
        ("echo .mcp.json", false),
        ("docker cp c:/x ./out", false),
        ("docker cp .mcp.json ctr:/x", false),
        ("zip out.zip src/*", false),
        ("cp a b", false),
        ("less -o .mcp.json README.md", true),
        ("less -O .mcp.json README.md", true),
        ("sort -o .mcp.json in", true),
        ("git diff --output=.mcp.json", true),
        ("find . -fprint .mcp.json", true),
        ("tree -o .mcp.json", true),
    ]);
}

/// Sweep table, one row per program of the receipt's 98-program table plus the new ones, each with the protected path
/// in a position the specific classifier does not expect (an option value, a trailing word, a script body).
/// `blocked=false` rows document that a protected path in a pure INPUT position is a read.
#[test]
fn p166_r7_sweep_table_unexpected_positions() {
    check(&[
        ("cp -v --backup=numbered a .mcp.json", true),
        ("mv a .mcp.json -f", true),
        ("ln -sf a .mcp.json", true),
        ("install -m 755 a .git/hooks/pre-commit", true),
        ("rm -f out/x .mcp.json", true),
        ("rmdir out .fuigo", true),
        ("mkdir -p out .mcp.json", true),
        ("touch -d now .mcp.json", true),
        ("truncate -s 0 .mcp.json", true),
        ("tee -a out/x .mcp.json", true),
        ("dd if=a bs=1 of=.mcp.json", true),
        ("uniq in .mcp.json", true),
        ("sort in -o .mcp.json", true),
        ("rustc a.rs --out-dir .fuigo", true),
        ("rustfmt out/a.rs .mcp.json", true),
        ("go build -o .mcp.json ./...", true),
        ("tar -cf .mcp.json src", true),
        ("gtar -C .fuigo -xf a.tar", true),
        ("bsdtar -cf .mcp.json src", true),
        ("unzip -d .fuigo a.zip", true),
        ("zip .mcp.json src", true),
        ("zip -r out.zip src .mcp.json", false),
        ("rsync -a src/ .fuigo/", true),
        ("ditto src .fuigo", true),
        ("cpio -o -O .mcp.json", true),
        ("7z a .mcp.json src", true),
        ("pax -w -f .mcp.json src", true),
        ("patch -p1 -o .mcp.json p.diff", true),
        ("scp host:x .mcp.json", true),
        ("sftp -b .mcp.json host", true),
        ("curl -s https://x.invalid -o .mcp.json", true),
        ("wget -q -O .mcp.json https://x.invalid", true),
        ("split -l 5 in .mcp.json", true),
        ("csplit in 3 -f .mcp.json", true),
        ("gunzip -k .mcp.json.gz", true),
        ("gzip -d -k .mcp.json.gz", true),
        ("zstd -d a.zst -o .mcp.json", true),
        ("xz -d -k .mcp.json.xz", true),
        ("bzip2 -dk .mcp.json.bz2", true),
        ("sed -i s/a/b/ out/x .mcp.json", true),
        ("gsed -i s/a/b/ out/x .mcp.json", true),
        ("perl -pi -e s/a/b/ .mcp.json", true),
        ("ruby -pi -e '$_' .mcp.json", true),
        ("yq -i .a=1 .mcp.json", true),
        ("awk 'BEGIN{print \"x\" > \".mcp.json\"}'", true),
        ("gawk 'BEGIN{print \"x\" > \".mcp.json\"}'", true),
        ("sponge out/x .mcp.json", true),
        ("find . -fprint .mcp.json", true),
        ("find . -name x -exec touch .mcp.json +", true),
        ("xargs touch .mcp.json", true),
        ("env A=1 touch .mcp.json", true),
        ("sudo -u root cp a .mcp.json", true),
        ("nohup touch .mcp.json", true),
        ("timeout 5 touch .mcp.json", true),
        ("git diff --output=.mcp.json", true),
        ("cc a.c -o .mcp.json", true),
        ("gcc -o .mcp.json a.c", true),
        ("clang -c a.c -o .mcp.json", true),
        ("tcc a.c -o .mcp.json", true),
        ("ld -o .mcp.json a.o", true),
        ("strip -o .mcp.json a", true),
        ("dot -Tpng -o .mcp.json g.dot", true),
        ("pandoc in.md -o .mcp.json", true),
        ("openssl enc -in a -out .mcp.json", true),
        ("xxd -r in .mcp.json", true),
        ("iconv -f a -t b -o .mcp.json in", true),
        ("base64 -d in -o .mcp.json", true),
        ("ed -s out/x .mcp.json", true),
        ("ex -s -c wq .mcp.json", true),
        ("vi -c 'w .mcp.json' a", true),
        ("vim -c 'w .mcp.json' a", true),
        ("nvim -c 'w .mcp.json' a", true),
        ("emacs --eval '(write-file \".mcp.json\")' a", true),
        ("nano -w .mcp.json", true),
        ("mkfifo -m 600 .mcp.json", true),
        ("mknod -m 600 .mcp.json p", true),
        ("shred -u .mcp.json", true),
        ("rename -v s/a/b/ .mcp.json", true),
        ("unlink .mcp.json", true),
        ("chmod 600 .mcp.json", false),
        ("chown me .mcp.json", false),
        ("docker cp c:/x .mcp.json", true),
        ("kubectl cp ns/pod:/x .mcp.json", true),
        ("podman cp c:/x .mcp.json", true),
        ("ssh -E .mcp.json host", true),
        ("ffmpeg -i a.mp4 .mcp.json -y", true),
        ("convert a.png .mcp.json -quality 80", true),
        ("mogrify -format png .mcp.json", true),
        ("ar -r .mcp.json a.o", true),
        ("sqlite3 .mcp.json 'create table t(a)'", true),
        ("python -c \"open('.mcp.json','w')\"", true),
        ("python3 -c \"open('.mcp.json','w')\"", true),
        ("node -e \"require('fs').writeFileSync('.mcp.json','')\"", true),
        ("deno eval 'Deno.writeTextFileSync(\".mcp.json\", \"\")'", true),
        ("php -r 'file_put_contents(\".mcp.json\", \"\");'", true),
        ("lua -e 'io.open(\".mcp.json\", \"w\")'", true),
        ("open .mcp.json", true),
        ("xdg-open .mcp.json", true),
        ("tr a b < in > .mcp.json", true),
        ("mktemp .mcp.json.XXXX", false),
        ("jq . .mcp.json", false),
        ("pbcopy < .mcp.json", false),
    ]);
}

/// The false-positive suite named in the round-7 brief. Prints one `FP <command> => <floor>` line per command (run it
/// at the integration base and at the tip with `--nocapture` to compare) and asserts the floor stays silent.
#[test]
fn p166_r7_false_positive_suite() {
    let project = tempfile::tempdir().unwrap();
    let cwd = project.path();
    std::fs::create_dir_all(cwd.join("out")).unwrap();
    std::fs::create_dir_all(cwd.join("src")).unwrap();
    let suite = [
        "ffmpeg -i a.mp4 out/b.mp4",
        "convert a.png b.png",
        "zip out.zip src/*",
        "vim README.md",
        "docker cp c:/x ./out",
        "git checkout main",
        "git switch main",
        "git pull",
        "git stash pop",
        "cat ~/.bashrc",
        "grep -r hooks .git/hooks",
        "ls -la .git/hooks",
        "rsync -a src/ dst/",
        "python3 script.py",
        "node build.js",
        "cp a b",
        "sed -n 1,5p .mcp.json",
    ];
    let mut loud = Vec::new();
    for cmd in suite {
        let got = floor_in(cwd, cmd);
        eprintln!("FP {cmd} => {got:?}");
        if got.is_some() {
            loud.push(*cmd.split(' ').next().iter().next().unwrap_or(&""));
            loud.push(cmd);
        }
    }
    assert!(loud.is_empty(), "false positives: {loud:?}");
}
