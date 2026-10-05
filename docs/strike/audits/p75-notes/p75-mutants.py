import subprocess,sys,os,datetime
SRC="/root/fuigo-builds/p75/src"; LOG=open("/root/fuigo-builds/p75/mutants.log","a")
ENV=dict(os.environ,PATH=os.environ["HOME"]+"/.cargo/bin:"+os.environ["PATH"],CARGO_TARGET_DIR="/root/fuigo-builds/p75/target",RUST_MIN_STACK="16777216",CARGO_TERM_COLOR="never",RG_BIN_PATH="/usr/bin/rg",CARGO_BUILD_JOBS="16")
def sh(cmd):
    p=subprocess.run(cmd,shell=True,cwd=SRC,env=ENV,capture_output=True,text=True); return p.returncode,p.stdout+p.stderr
def log(s): LOG.write(s+"\n"); LOG.flush()
T_PAGER="/root/fuigo-builds/slot-run.sh p75 nice -n 10 timeout 1800 cargo test --locked -p fuigo-pager-bin --test dead_output_sweep"
T_WS="/root/fuigo-builds/slot-run.sh p75 nice -n 10 timeout 1800 cargo test --locked -p fuigo-workspace --test workspace_server_dead_output"
def CLIP(p): return "nice -n 10 cargo clippy --locked -p %s --message-format=short"%p
M=[
 ("MU1","crates/codegen/fuigo-update/src/auto_update.rs",'fuigo_tty_utils::cli_eprintln!("Switched to {} channel.", ch);','eprintln!("Switched to {} channel.", ch);',[T_PAGER,CLIP("fuigo-update")]),
 ("MU2","crates/codegen/fuigo-update/src/auto_update.rs",'fuigo_tty_utils::cli_println!("Update check failed: {error}");','println!("Update check failed: {error}");',[T_PAGER,CLIP("fuigo-update")]),
 ("MU3","crates/codegen/fuigo-workspace/src/bin/workspace_server.rs",'fuigo_tty_utils::cli_println!("{}", serde_json::to_string(&CAPABILITIES)?);','println!("{}", serde_json::to_string(&CAPABILITIES)?);',[T_WS,CLIP("fuigo-workspace")]),
 ("MU4","crates/codegen/fuigo-workspace/src/bin/workspace_server.rs",'if fuigo_tty_utils::best_effort_stdout::hard_failure() {','if false {',[T_WS]),
 ("MU5","crates/codegen/fuigo-workspace/src/bin/workspace_server.rs",'fuigo_tty_utils::cli_eprintln!("{msg}");','eprintln!("{msg}");',[T_WS,CLIP("fuigo-workspace")]),
 ("MU6","crates/codegen/fuigo-telemetry/src/external/providers.rs",'            fuigo_tty_utils::cli_eprintln!(\n                "[external-otel] event=','            eprintln!(\n                "[external-otel] event=',[T_PAGER,CLIP("fuigo-telemetry")]),
 ("ML1","crates/codegen/fuigo-sandbox/src/lib.rs",'fuigo_tty_utils::cli_eprintln!("error: could not prepare the bwrap containment sentinel: {e}");','eprintln!("error: could not prepare the bwrap containment sentinel: {e}");',[CLIP("fuigo-sandbox")]),
 ("ML2","crates/codegen/fuigo-workspace-daemon/src/daemonize.rs",'fuigo_tty_utils::cli_eprintln!("taking over from predecessor','eprintln!("taking over from predecessor',[CLIP("fuigo-workspace-daemon")]),
 ("ML3","crates/codegen/fuigo-pager-render/src/lib.rs",None,'\npub fn __r077_probe() { println!("x"); dbg!(1); }\n',[CLIP("fuigo-pager-render")]),
 ("ML4","crates/codegen/fuigo-markdown/src/lib.rs",None,'\npub fn __r077_probe() { eprint!("x"); }\n',[CLIP("fuigo-markdown")]),
]
only=sys.argv[1:]
log("### mutants at %s"%sh("git rev-parse HEAD")[1].strip())
for mid,f,old,new,cmds in M:
    if only and mid not in only: continue
    p=os.path.join(SRC,f); s=open(p).read()
    if old is None: s2=s+new
    else:
        assert old in s,(mid,old); s2=s.replace(old,new,1)
    open(p,"w").write(s2)
    log("=== %s %s %s"%(mid,datetime.datetime.utcnow().isoformat()+"Z",f))
    for c in cmds:
        rc,out=sh(c)
        keep=[l for l in out.split("\n") if l.startswith("test ") or "test result" in l or "expected exit" in l or ": error" in l]
        log("  $ %s\n  rc=%d\n    %s"%(c,rc,"\n    ".join(keep[:14])))
    sh("git checkout -- "+f)
    log("  restored; dirty=%s"%sh("git status --porcelain | wc -l")[1].strip())
log("MUTANTSDONE")
