//! Sets `cfg(f5_trace_control)` (the B-F5 paused-writer negative control, design F5 §9.4) when the build runs with
//! `FUIGO_F5_TRACE_CONTROL=1`. Never set for a shipped build.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(f5_trace_control)");
    println!("cargo::rerun-if-env-changed=FUIGO_F5_TRACE_CONTROL");
    if std::env::var_os("FUIGO_F5_TRACE_CONTROL").is_some_and(|value| value == "1") {
        println!("cargo::rustc-cfg=f5_trace_control");
    }
}
