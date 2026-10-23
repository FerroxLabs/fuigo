use super::*;

fn at(base: Instant, secs: f32) -> Instant {
    base + Duration::from_secs_f32(secs)
}

#[test]
fn angle_is_continuous_one_revolution_and_ends_at_rest() {
    assert_eq!(angle_at(0.0), 0.0);
    assert!(
        (angle_at(2.5) - TAU * 0.5).abs() < 1e-4,
        "5 s per revolution while cruising"
    );
    let eps = 1e-3;
    assert!((angle_at(CRUISE_SECS - eps) - angle_at(CRUISE_SECS + eps)).abs() < 0.01);
    assert!(
        (angle_at(SPIN_TOTAL_SECS - eps) - TAU).abs() < 0.01,
        "lands on a full turn"
    );
    assert_eq!(angle_at(SPIN_TOTAL_SECS), 0.0);
    assert_eq!(angle_at(SPIN_TOTAL_SECS + 50.0), 0.0);
    let (mut prev, mut t) = (0.0, 0.0);
    while t < SPIN_TOTAL_SECS {
        let a = angle_at(t);
        assert!(a >= prev, "angle must not run backwards at {t}");
        prev = a;
        t += 0.01;
    }
}

#[test]
fn rest_pose_is_exactly_forward_and_deterministic() {
    assert_eq!(Pose::REST.theta, 0.0);
    assert_eq!(pose_at(SPIN_TOTAL_SECS), Pose::REST);
    assert_eq!(pose_at(SPIN_TOTAL_SECS + 100.0), Pose::REST);
    assert_eq!(pose_at(1.0), pose_at(1.0));
}

#[test]
fn the_gust_plays_once_as_the_mark_settles() {
    assert_eq!(pose_at(0.0).gust, None);
    assert_eq!(pose_at(GUST_START_SECS - 0.01).gust, None);
    let mut seen = Vec::new();
    let mut t = 0.0;
    while t < SPIN_TOTAL_SECS + 2.0 {
        seen.push(pose_at(t).gust.is_some());
        t += 0.01;
    }
    // One contiguous window: false..., true..., false... with exactly two transitions
    let flips = seen.windows(2).filter(|w| w[0] != w[1]).count();
    assert_eq!(flips, 2, "gust must be a single window");
    let p = pose_at(GUST_START_SECS + GUST_SECS / 2.0).gust.unwrap();
    assert!((p - 0.5).abs() < 0.02, "{p}");
    assert_eq!(pose_at(SPIN_TOTAL_SECS).gust, None);
}

#[test]
fn guards_disable_animation() {
    let none = |_: &str| false;
    assert!(AnimEnv::from_vars(none, false).allows_animation());
    for var in ["SSH_CONNECTION", "SSH_TTY", "NO_COLOR"] {
        let env = AnimEnv::from_vars(|k| k == var, false);
        assert!(!env.allows_animation(), "{var} must disable animation");
        assert!(env.disabled_reason().is_some());
    }
    assert!(
        !AnimEnv::from_vars(none, true).allows_animation(),
        "ui.animations=false / ui.background_mark_animate=false"
    );
}

#[test]
fn disabled_animation_shows_the_settled_frame_at_every_instant() {
    let t0 = Instant::now();
    let anim = Anim::new(t0);
    let mut s = 0.0;
    while s < 8.0 {
        assert_eq!(anim.pose(at(t0, s), false), Pose::REST);
        assert_eq!(anim.frame(at(t0, s), false), REST_FRAME);
        s += 0.25;
    }
    assert_ne!(
        anim.pose(at(t0, 1.0), true),
        Pose::REST,
        "enabled, the same instant spins"
    );
}

#[test]
fn keypress_stops_the_animation() {
    let t0 = Instant::now();
    let mut anim = Anim::new(t0);
    assert_ne!(anim.pose(at(t0, 1.0), true), Pose::REST);
    assert_ne!(anim.frame(at(t0, 1.0), true), REST_FRAME);
    anim.snap_to_rest();
    assert_eq!(anim.pose(at(t0, 1.1), true), Pose::REST);
    assert_eq!(anim.frame(at(t0, 1.1), true), REST_FRAME);
    assert_eq!(anim.frame(at(t0, 2.0), true), REST_FRAME);
}

#[test]
fn spin_replays_on_return_but_not_on_every_tick() {
    let t0 = Instant::now();
    let mut anim = Anim::new(t0);
    for i in 1..=20 {
        anim.note_visible(at(t0, i as f32 * 0.083));
    }
    assert!(
        anim.pose(at(t0, 1.7), true).theta > 0.0,
        "regular ticks must not restart the spin"
    );
    anim.note_visible(at(t0, 9.0));
    anim.snap_to_rest();
    assert_eq!(anim.pose(at(t0, 9.1), true), Pose::REST);
    // Away longer than the replay gap, then back: it plays again from the start
    anim.note_visible(at(t0, 30.0));
    assert!(anim.pose(at(t0, 31.0), true).theta > 0.0);
    assert!(anim.frame(at(t0, 31.0), true) < REST_FRAME);
}

#[test]
fn focus_loss_shows_rest_and_focus_return_resumes() {
    let t0 = Instant::now();
    let mut anim = Anim::new(t0);
    let before = anim.pose(at(t0, 2.0), true);
    anim.set_focused(at(t0, 2.0), false);
    assert_eq!(anim.pose(at(t0, 3.0), true), Pose::REST);
    assert_eq!(
        anim.frame(at(t0, 50.0), true),
        REST_FRAME,
        "no frames while unfocused"
    );
    anim.set_focused(at(t0, 60.0), true);
    let after = anim.pose(at(t0, 60.0), true);
    assert!(
        (after.theta - before.theta).abs() < 1e-3,
        "resumed at {after:?}, left at {before:?}"
    );
}

#[test]
fn no_frames_after_rest() {
    let t0 = Instant::now();
    let anim = Anim::new(t0);
    let mut frames = std::collections::BTreeSet::new();
    let mut s = 0.0;
    while s < SPIN_TOTAL_SECS {
        frames.insert(anim.frame(at(t0, s), true));
        s += 1.0 / 60.0;
    }
    assert!(frames.iter().all(|&f| f < REST_FRAME));
    // About SPIN_FPS distinct frames per second: the redraw throttle
    let expected = (SPIN_TOTAL_SECS * SPIN_FPS) as usize;
    assert!(
        (expected - 2..=expected + 2).contains(&frames.len()),
        "{} frames",
        frames.len()
    );
    for s in [SPIN_TOTAL_SECS + 0.001, SPIN_TOTAL_SECS + 1.0, 60.0, 3600.0] {
        assert_eq!(anim.frame(at(t0, s), true), REST_FRAME, "at {s}");
        assert_eq!(anim.pose(at(t0, s), true), Pose::REST);
    }
}

#[test]
fn the_live_clock_never_spins_under_test() {
    assert_eq!(current_pose(), Pose::REST);
    assert_eq!(mark_frame(), REST_FRAME);
}

#[test]
fn frames_stop_advancing_while_the_mark_is_not_on_screen() {
    let t0 = Instant::now();
    assert!(
        !still_visible(None, t0),
        "never painted: nothing to animate"
    );
    assert!(still_visible(Some(t0), at(t0, 0.1)));
    assert!(
        !still_visible(Some(t0), at(t0, 5.0)),
        "hidden for longer than the freshness window"
    );
}
