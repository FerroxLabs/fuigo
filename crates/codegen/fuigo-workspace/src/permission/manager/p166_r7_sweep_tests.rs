//! P166 round 7: table-driven writer sweep. One row per program of the receipt's writer table (the 98 programs of the
//! round 5/6 sweep plus the programs added in round 7). Every writer row carries at least two argv templates: the
//! protected path in the position the specific classifier expects, and in a position it does not (an option value,
//! after `--`, not last, a script body). `{P}` is replaced with each of two protected paths, so each template runs twice.

use super::{PermissionState, bash_protected_write_target, evaluate_bash};

/// The eight rows round 7 left out as uncovered (scp `-o` value, wget `-P`, docker `-H` and `--context`, tar
/// `--index-file`, curl `--output-dir`, rsync `--temp-dir` and `-e`) are back in this table (round 8).
///
/// `(program, argv templates)`. Writers: the protected floor must fire for every template and both paths.
pub(super) const WRITERS: &[(&str, &[&str])] = &[
    // Round 8B: a metadata change that makes a hook executable is a protected hit (literal hook paths, no `{P}`).
    ("chmod", &["chmod +x .git/hooks/pre-commit", "chmod -R +x .git"]),
    ("chown", &["chown me .git/hooks/pre-commit", "chown -R me -- .git"]),
    ("chgrp", &["chgrp staff .git/hooks/pre-commit", "chgrp -R staff -- .git"]),
    ("cp", &["cp a {P}", "cp -v a -- {P}", "cp a {P} -v", "cp --backup=numbered a {P}"]),
    ("mv", &["mv a {P}", "mv a {P} -f", "mv -t {P} a"]),
    ("ln", &["ln -s a {P}", "ln -sf -- a {P}"]),
    ("install", &["install a {P}", "install -t {P} a", "install -m 644 a {P} -v"]),
    ("rm", &["rm {P}", "rm -f -- {P}", "rm -f out/x {P}"]),
    ("rmdir", &["rmdir {P}", "rmdir -p -- {P}"]),
    ("mkdir", &["mkdir {P}", "mkdir -m 700 -- {P}", "mkdir -p out {P}"]),
    ("touch", &["touch {P}", "touch -- {P}", "touch -d now {P}"]),
    ("truncate", &["truncate -s 0 {P}", "truncate -s 0 -- {P}"]),
    ("tee", &["echo x | tee {P}", "echo x | tee -a out/x {P}"]),
    ("dd", &["dd of={P}", "dd if=a of={P} bs=1", "dd if=a bs=1 of={P}"]),
    ("uniq", &["uniq in {P}", "uniq -- in {P}"]),
    ("sort", &["sort -o {P} in", "sort in --output={P}", "sort in -o {P}"]),
    ("rustc", &["rustc -o {P} a.rs", "rustc a.rs --out-dir {P}", "rustc a.rs -o{P}"]),
    ("rustfmt", &["rustfmt {P}", "rustfmt --edition 2021 -- {P}"]),
    ("go", &["go build -o {P} ./...", "go build ./... -o {P}"]),
    ("tar", &["tar -cf {P} src", "tar -c src -f {P}", "tar --create --file={P} src", "tar -cf a.tar src --index-file {P}", "tar -xf a.tar -C {P}"]),
    ("gtar", &["gtar -cf {P} src", "gtar -c src -f {P}", "gtar -C {P} -xf a.tar"]),
    ("bsdtar", &["bsdtar -cf {P} src", "bsdtar -c src -f {P}", "bsdtar -xf a.tar -C {P}"]),
    ("unzip", &["unzip -d {P} a.zip", "unzip a.zip -d {P}"]),
    ("zip", &["zip {P} src", "zip -r -- {P} src", "zip -q {P} src"]),
    ("rsync", &["rsync -a src/ {P}", "rsync -a src/ out/ --log-file={P}", "rsync -a src/ out/ --write-batch={P}", "rsync -a --log-file {P} src/ out/", "rsync -a src/ out/ --temp-dir {P}", "rsync -a src/ out/ -e 'ssh -E {P}'", "rsync -a -b --backup-dir {P} src/ dest/", "rsync -a --partial-dir {P} src/ dest/"]),
    ("ditto", &["ditto src {P}", "ditto -V src {P}"]),
    ("cpio", &["cpio -o -O {P}", "cpio -o --file={P}"]),
    ("7z", &["7z a {P} src", "7z a -tzip {P} src", "7z x a.7z -o{P}"]),
    ("7za", &["7za a {P} src", "7za a -tzip {P} src"]),
    ("7zz", &["7zz a {P} src", "7zz a -tzip {P} src"]),
    ("7zr", &["7zr a {P} src", "7zr a -t7z {P} src"]),
    ("pax", &["pax -w -f {P} src", "pax -wf {P} src", "pax -r -s ',a,b,' -f a.tar {P}"]),
    ("patch", &["patch -o {P} f p.diff", "patch --output={P} f p.diff", "patch -p1 {P} p.diff"]),
    ("scp", &["scp host:x {P}", "scp -q -- host:x {P}", "scp -o 'UserKnownHostsFile={P}' host:x out/"]),
    ("sftp", &["sftp host:x {P}", "sftp -o 'UserKnownHostsFile={P}' host"]),
    ("curl", &["curl -o {P} https://x.invalid", "curl https://x.invalid --output {P}", "curl -sS https://x.invalid -D {P}", "curl --output-dir {P} -O https://x.invalid/f"]),
    ("wget", &["wget -O {P} https://x.invalid", "wget -q https://x.invalid -O{P}", "wget https://x.invalid -P {P}"]),
    ("split", &["split in {P}", "split -l 5 -- in {P}"]),
    ("csplit", &["csplit -f {P} in 3", "csplit in 3 --prefix={P}"]),
    ("gunzip", &["gunzip {P}.gz", "gunzip -k -- {P}.gz"]),
    ("gzip", &["gzip -d {P}.gz", "gzip -dk -- {P}.gz"]),
    ("zstd", &["zstd -d {P}.zst", "zstd -d a.zst -o {P}"]),
    ("xz", &["xz -d {P}.xz", "xz -dk -- {P}.xz"]),
    ("bzip2", &["bzip2 -d {P}.bz2", "bzip2 -dk -- {P}.bz2"]),
    ("sed", &["sed -i s/a/b/ {P}", "sed -i s/a/b/ out/x {P}", "sed -e 's/a/b/w {P}' in", "sed -n 'w {P}' in"]),
    ("gsed", &["gsed -i s/a/b/ {P}", "gsed -e 's/a/b/w {P}' in"]),
    ("perl", &["perl -pi -e s/a/b/ {P}", "perl -e 'open F, \">{P}\"'"]),
    ("ruby", &["ruby -pi -e '$_' {P}", "ruby -e 'File.write(\"{P}\", \"x\")'"]),
    ("yq", &["yq -i .a=1 {P}", "yq -i -- .a=1 {P}", "yq -i .a=1 out/x {P}"]),
    ("awk", &["awk 'BEGIN{print \"x\" > \"{P}\"}'", "awk '{print > \"{P}\"}' in"]),
    ("gawk", &["gawk 'BEGIN{print \"x\" > \"{P}\"}'", "gawk '{print > \"{P}\"}' in"]),
    ("mawk", &["mawk 'BEGIN{print \"x\" > \"{P}\"}'"]),
    ("nawk", &["nawk 'BEGIN{print \"x\" > \"{P}\"}'"]),
    ("sponge", &["echo x | sponge {P}", "echo x | sponge -a {P}"]),
    ("find", &["find . -fprint {P}", "find . -name x -exec touch {P} +", "find . -exec cp a {P} ;"]),
    ("xargs", &["xargs touch {P}", "xargs -I{} cp {} {P}"]),
    ("env", &["env A=1 touch {P}", "env -i touch -- {P}"]),
    ("sudo", &["sudo cp a {P}", "sudo -u root -- cp a {P}"]),
    ("nohup", &["nohup touch {P}", "nohup cp a {P}"]),
    ("timeout", &["timeout 5 touch {P}", "timeout -s KILL 5 cp a {P}"]),
    ("git", &["git diff --output={P}", "git checkout -- {P}", "git config --file {P} a.b c", "git -c core.hooksPath={P} status", "git restore -- {P}", "git -ccore.hooksPath={P} commit", "git --config-e=core.hooksPath={P} commit", "git --config-env core.hooksPath={P} commit", "git -c include.path={P} commit"]),
    ("cc", &["cc -o {P} a.c", "cc a.c -o {P}", "cc a.c -MF {P}"]),
    ("gcc", &["gcc -o {P} a.c", "gcc a.c -o{P}"]),
    ("clang", &["clang -c a.c -o {P}", "clang -o {P} a.c"]),
    ("tcc", &["tcc a.c -o {P}", "tcc -o {P} a.c"]),
    ("ld", &["ld -o {P} a.o", "ld a.o -o {P}"]),
    ("strip", &["strip -o {P} a", "strip a -o {P}"]),
    ("dot", &["dot -o {P} g.dot", "dot -Tpng g.dot -o{P}"]),
    ("pandoc", &["pandoc in.md -o {P}", "pandoc in.md --output={P}"]),
    ("openssl", &["openssl enc -in a -out {P}", "openssl req -new -keyout {P}"]),
    ("xxd", &["xxd -r in {P}", "xxd -r -- in {P}"]),
    ("iconv", &["iconv -f a -t b -o {P} in", "iconv in --output={P}"]),
    ("base64", &["base64 -d in -o {P}", "base64 --output={P} in"]),
    ("ed", &["ed {P}", "ed -s out/x {P}", "ed -s -- {P}"]),
    ("ex", &["ex {P}", "ex -s -c 'w {P}' a", "ex -s -c wq {P}"]),
    ("vi", &["vi {P}", "vi -c 'w {P}' a"]),
    ("vim", &["vim {P}", "vim -c 'w! {P}' a", "vim --cmd 'w {P}' a", "vim '+w {P}' a"]),
    ("nvim", &["nvim {P}", "nvim -c 'wq {P}' a"]),
    ("emacs", &["emacs {P}", "emacs --eval '(write-file \"{P}\")' a"]),
    ("nano", &["nano {P}", "nano -w -- {P}"]),
    ("sqlite3", &["sqlite3 {P} 'create table t(a)'", "sqlite3 a.db '.backup {P}'"]),
    ("python", &["python x.py {P}", "python -c \"open('{P}','w')\""]),
    ("python3", &["python3 x.py {P}", "python3 -c \"open('{P}','w')\""]),
    ("node", &["node x.js {P}", "node -e \"require('fs').writeFileSync('{P}','')\""]),
    ("deno", &["deno run x.ts {P}", "deno eval 'Deno.writeTextFileSync(\"{P}\", \"\")'"]),
    ("php", &["php x.php {P}", "php -r 'file_put_contents(\"{P}\", \"\");'"]),
    ("lua", &["lua x.lua {P}", "lua -e 'io.open(\"{P}\", \"w\")'"]),
    ("mkfifo", &["mkfifo {P}", "mkfifo -m 600 -- {P}"]),
    ("mknod", &["mknod {P} p", "mknod -m 600 {P} p"]),
    ("shred", &["shred -u {P}", "shred -n 1 -- {P}"]),
    ("rename", &["rename s/a/b/ {P}", "rename -v -- s/a/b/ {P}"]),
    ("unlink", &["unlink {P}", "unlink -- {P}"]),
    ("docker", &["docker cp c:/x {P}", "docker cp -a c:/x {P}", "docker -H unix:///x cp c:/x {P}", "docker --context c cp c:/x {P}", "docker run -v {P}:/h alpine ls"]),
    ("podman", &["podman cp c:/x {P}", "podman cp -a c:/x {P}", "podman run --volume {P}:/h alpine ls"]),
    ("kubectl", &["kubectl cp ns/pod:/x {P}", "kubectl cp -c ctr ns/pod:/x {P}"]),
    ("ssh", &["ssh -E {P} host", "ssh -o 'UserKnownHostsFile={P}' host"]),
    ("ffmpeg", &["ffmpeg -i a {P}", "ffmpeg -i a {P} -y", "ffmpeg -y -i a {P} -loglevel error"]),
    ("convert", &["convert a.png {P}", "convert a.png {P} -quality 80", "convert a.png -write {P} out.png"]),
    ("magick", &["magick a.png {P}", "magick a.png {P} -quality 80"]),
    ("mogrify", &["mogrify -format png {P}", "mogrify -path {P} a.png"]),
    ("ar", &["ar r {P} a.o", "ar -rcs {P} a.o", "ar rcs {P} a.o"]),
    ("mktemp", &["mktemp -p {P}", "mktemp --tmpdir={P}"]),
    ("tr", &["tr a b < in > {P}", "tr -d x < in | tee {P}"]),
    ("open", &["open {P}", "open -a Editor {P}"]),
    ("xdg-open", &["xdg-open {P}", "xdg-open -- {P}"]),
    ("less", &["less -o {P} README.md", "less -O {P} README.md", "less --log-file={P} README.md"]),
    ("tree", &["tree -o {P}", "tree src -o {P}"]),
    ("jq-redirect", &["jq . in > {P}", "jq . in >> {P}"]),
];

/// Programs of the sweep that never name a file written: a protected path is a read or metadata. The floor stays silent
/// (documented in the receipt: `chmod`/`chown`/`chgrp` metadata only, `jq`/`pbcopy` read only).
const NON_WRITERS: &[(&str, &[&str])] = &[
    // Round 8B: metadata on a protected FILE stays silent; the hook rows (a hook is executable by metadata alone) are in
    // [`WRITERS`]. These rows name `.mcp.json` literally, so both `{P}` passes run the same silent case.
    ("chmod", &["chmod 600 .mcp.json", "chmod -R 600 -- .mcp.json"]),
    ("chown", &["chown me .mcp.json", "chown -R me -- .mcp.json"]),
    ("chgrp", &["chgrp staff .mcp.json", "chgrp -R staff -- .mcp.json"]),
    ("jq", &["jq . {P}", "jq -r .a -- {P}"]),
    ("pbcopy", &["pbcopy < {P}", "cat {P} | pbcopy"]),
];

/// Every program of the receipt's 98-program table plus the round-7 additions. The coverage test fails when a program
/// is missing from [`WRITERS`] / [`NON_WRITERS`].
const SWEEP_PROGRAMS: &[&str] = &[
    "cp", "mv", "ln", "install", "rm", "rmdir", "mkdir", "touch", "truncate", "tee", "dd", "uniq", "sort", "rustc",
    "rustfmt", "go", "tar", "gtar", "bsdtar", "unzip", "zip", "rsync", "ditto", "cpio", "7z", "pax", "patch", "scp",
    "sftp", "curl", "wget", "split", "csplit", "gunzip", "gzip", "zstd", "xz", "bzip2", "sed", "gsed", "perl", "ruby",
    "yq", "awk", "gawk", "sponge", "find", "xargs", "env", "sudo", "nohup", "timeout", "git", "cc", "gcc", "clang",
    "pandoc", "openssl", "xxd", "iconv", "ed", "ex", "vi", "vim", "nvim", "emacs", "nano", "sqlite3", "python",
    "python3", "node", "deno", "php", "lua", "mkfifo", "mknod", "shred", "rename", "unlink", "chmod", "chown",
    "docker", "kubectl", "ssh", "ffmpeg", "convert", "ar", "tcc", "ld", "strip", "dot", "mktemp", "tr", "base64", "jq",
    "xdg-open", "open", "pbcopy",
    // Round 7 additions.
    "chgrp", "podman", "magick", "mogrify", "mawk", "nawk", "7za", "7zz", "7zr", "less", "tree",
];

pub(super) const PROTECTED_PATHS: &[&str] = &[".mcp.json", ".git/hooks/pre-commit"];

fn floor_for(cwd: &std::path::Path, cmd: &str) -> Option<crate::permission::shell_access::ProtectedEditReason> {
    let state = PermissionState::default();
    let evaluation = evaluate_bash(cmd, &state, true);
    bash_protected_write_target(&evaluation, cwd, None)
}

fn run(table: &[(&str, &[&str])], blocked: bool) {
    let project = tempfile::tempdir().unwrap();
    let cwd = project.path();
    std::fs::create_dir_all(cwd.join("out")).unwrap();
    std::fs::create_dir_all(cwd.join("src")).unwrap();
    let (mut wrong, mut cases) = (Vec::new(), 0usize);
    for (program, templates) in table {
        assert!(templates.len() >= 2 || *program == "mawk" || *program == "nawk", "{program}: needs two argv");
        for template in *templates {
            for path in PROTECTED_PATHS {
                let cmd = template.replace("{P}", path);
                cases += 1;
                let got = floor_for(cwd, &cmd);
                if got.is_some() != blocked {
                    wrong.push(format!("[{program}] {cmd}: expected floor={blocked}, got {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{} of {cases} sweep cases wrong:\n{}", wrong.len(), wrong.join("\n"));
}

/// Every writer program fires the protected floor for the classifier's own position and for an unexpected one.
#[cfg(unix)]
#[test]
fn p166_r7_sweep_writers_fire_floor_in_every_position() {
    run(WRITERS, true);
}

/// Metadata-only and read-only programs stay silent for a protected path.
#[cfg(unix)]
#[test]
fn p166_r7_sweep_non_writers_stay_silent() {
    run(NON_WRITERS, false);
}

/// The table accounts for every program of the sweep list (mechanical coverage of the receipt table).
#[test]
fn p166_r7_sweep_table_covers_every_program() {
    let have: Vec<&str> = WRITERS.iter().chain(NON_WRITERS).map(|(program, _)| *program).collect();
    let missing: Vec<&&str> = SWEEP_PROGRAMS.iter().filter(|program| !have.contains(*program)).collect();
    assert!(missing.is_empty(), "programs without a sweep row: {missing:?}");
}
