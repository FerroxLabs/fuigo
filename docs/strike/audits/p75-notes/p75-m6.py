exec(open('/root/fuigo-builds/p75/mutants.py').read().split('M=[')[0])
M=[("MU12","third_party/tiff-0.11.3/src/decoder/ifd.rs",'return Err(TiffError::LimitsExceeded);','return Err(dbg!(TiffError::LimitsExceeded));',["/root/fuigo-builds/slot-run.sh p75 nice -n 10 timeout 1800 cargo test --locked -p fuigo-tools --test tiff_dead_stderr"]),
 ("ML6","third_party/usvg-0.47.0/src/text/colr.rs",'log::warn!("sweep gradients are not supported.");','println!("Warning: sweep gradients are not supported.");',["nice -n 10 cargo clippy --locked -p usvg --message-format=short"])]
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
