#!/usr/bin/env bash
# Self-test for check-token-leaks.py on a throwaway fixture. Fake tokens are assembled at run time so this
# file never holds one. Needs bash, python3, git.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
G=(python3 -I "$HERE/check-token-leaks.py")
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
body=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123
pass=0; fail=0
expect() { # <name> <want-rc> <command...>
  local name=$1 want=$2 rc=0; shift 2
  "$@" >"$W/out" 2>&1 || rc=$?
  if [ "$rc" = "$want" ]; then pass=$((pass+1)); echo "  ok   $name"; else fail=$((fail+1)); echo "  FAIL $name (rc=$rc want $want)"; cat "$W/out"; fi
}
mk() { printf '%s\n' "$2" > "$W/$1"; }
# unsplit: each vendor prefix followed by a token-length body
for pair in "sk_:live_${body}" "rk_:live_${body}" "shp:at_0123456789abcdef0123456789abcdef" "gh:p_${body}" "gh:o_${body}" \
            "github_:pat_${body}${body}" "xox:b-0123456789-abcdefghijkl" "AK:IA0123456789ABCDEF" "AI:za${body}" \
            "glp:at-${body}" "sk-:ant-api03-${body}"; do
  mk "bad.rs" "let t = \"${pair%%:*}${pair#*:}\";"
  expect "unsplit ${pair%%:*} is flagged" 1 "${G[@]}" --files "$W/bad.rs"
done
# split, bare prefixes, the AWS example and an explicit allow are clean
mk good.rs 'let t = concat!("sk_", "live_ABCDEFGHIJKLMNOPQRSTUVWX");'
expect "split token is clean" 0 "${G[@]}" --files "$W/good.rs"
mk good2.rs 'const PREFIXES: &[&str] = &["sk_live_", "rk_live_", "shpat_", "ghp_", "github_pat_", "xoxb-", "AKIA", "AIza", "glpat-"];'
expect "bare prefixes are clean" 0 "${G[@]}" --files "$W/good2.rs"
mk aws.md 'AKIAIOSFODNN7EXAMPLE'
expect "AWS documented example is clean" 0 "${G[@]}" --files "$W/aws.md"
mk allow.rs "let t = \"gh\"; // gh${body} leak-guard: allow"
expect "allow marker is honoured" 0 "${G[@]}" --files "$W/allow.rs"
# the report names path:line and never the token
mk bad.rs "let t = \"ghp_${body}\";"
expect "report omits the token" 1 "${G[@]}" --files "$W/bad.rs"
if grep -q "$body" "$W/out"; then fail=$((fail+1)); echo "  FAIL report leaked the token"; else pass=$((pass+1)); echo "  ok   report omits the token text"; fi
# tree mode on a throwaway repo: dirty tree fails, third_party is skipped, a split commit passes
R=$W/repo; mkdir -p "$R/third_party"; cd "$R"
GIT="git -c user.name=t -c user.email=t@t.invalid -c commit.gpgsign=false"
git init -q . ; printf 'let t = "ghp_%s";\n' "$body" > "$R/third_party/v.rs"; printf 'ok\n' > a.rs
$GIT add -A; $GIT commit -q -m one
expect "tree mode skips third_party" 0 "${G[@]}" HEAD
printf 'let t = "sk_live_%s";\n' "$body" > b.rs; $GIT add -A; $GIT commit -q -m two
expect "tree mode flags a bad commit" 1 "${G[@]}" HEAD
expect "tree mode on the parent is clean" 0 "${G[@]}" HEAD~1
echo "check-token-leaks: $pass passed, $fail failed"
[ "$fail" = 0 ]
