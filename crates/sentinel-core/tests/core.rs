use sentinel_core::{Decision, Signal, SentinelCore, State, MAX_EVENTS};

#[test]
fn shell_token_is_recorded() {
    let mut core = SentinelCore::new();
    core.scan(b"exec /system/bin/sh -c test");
    assert!(core.event_count() > 0);
    assert_eq!(core.event(0).unwrap().signal, Signal::ShellToken);
}

#[test]
fn multiple_signals_cross_breach_threshold() {
    let mut core = SentinelCore::new();
    core.observe(Signal::Debugger, 10);
    core.observe(Signal::Root, 20);
    assert_eq!(core.state(), State::Breached);
    assert_eq!(core.decision(), Decision::Block);
}

#[test]
fn ring_does_not_grow_beyond_capacity() {
    let mut core = SentinelCore::new();
    for i in 0..(MAX_EVENTS + 8) { core.observe(Signal::None, i); }
    assert_eq!(core.event_count(), MAX_EVENTS);
}
