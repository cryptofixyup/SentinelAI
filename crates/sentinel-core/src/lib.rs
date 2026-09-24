#![no_std]
#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicU8, Ordering};

pub const CACHE_LINE: usize = 64;
pub const MAX_EVENTS: usize = 32;
pub const MAX_INPUT: usize = 1024;
pub const ENTROPY_WINDOW: usize = 256;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Monitor = 0, Anomalous = 1, Breached = 2 }

impl State {
    #[inline(always)]
    pub const fn from_raw(v: u8) -> Self { match v { 0 => Self::Monitor, 1 => Self::Anomalous, _ => Self::Breached } }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision { Allow = 0, Monitor = 1, Block = 2 }

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    None = 0,
    ShellToken = 1,
    ProcSelfCmdline = 2,
    HighEntropy = 3,
    LowEntropy = 4,
    Tamper = 5,
    Debugger = 6,
    Root = 7,
    CertificateMismatch = 8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event { pub signal: Signal, pub severity: u8, pub offset: u16 }
impl Event { pub const EMPTY: Self = Self { signal: Signal::None, severity: 0, offset: 0 }; }

#[repr(align(64))]
pub struct EventRing { entries: [Event; MAX_EVENTS], head: usize, len: usize }

impl EventRing {
    pub const fn new() -> Self { Self { entries: [Event::EMPTY; MAX_EVENTS], head: 0, len: 0 } }
    #[inline(always)]
    pub fn push(&mut self, event: Event) {
        self.entries[self.head] = event;
        self.head = (self.head + 1) % MAX_EVENTS;
        if self.len < MAX_EVENTS { self.len += 1; }
    }
    #[inline(always)] pub const fn len(&self) -> usize { self.len }
    #[inline(always)]
    pub fn get(&self, index: usize) -> Option<Event> {
        if index >= self.len { return None; }
        let start = if self.len == MAX_EVENTS { self.head } else { 0 };
        Some(self.entries[(start + index) % MAX_EVENTS])
    }
}

#[repr(align(64))]
pub struct EntropyWindow { bytes: [u8; ENTROPY_WINDOW], len: usize }

impl EntropyWindow {
    pub const fn new() -> Self { Self { bytes: [0; ENTROPY_WINDOW], len: 0 } }
    #[inline(always)]
    pub fn load(&mut self, input: &[u8]) {
        let n = core::cmp::min(input.len(), ENTROPY_WINDOW);
        self.bytes[..n].copy_from_slice(&input[..n]);
        self.len = n;
    }
    #[inline]
    pub fn shannon_milli_bits(&self) -> u32 {
        if self.len == 0 { return 0; }
        let mut counts = [0u16; 256];
        let mut i = 0;
        while i < self.len { counts[self.bytes[i] as usize] = counts[self.bytes[i] as usize].saturating_add(1); i += 1; }
        let total = self.len as u32;
        let mut sum = 0u32;
        i = 0;
        while i < 256 {
            let c = counts[i] as u32;
            if c != 0 { sum = sum.saturating_add(entropy_term_milli(c, total)); }
            i += 1;
        }
        sum
    }
}

#[inline]
fn entropy_term_milli(count: u32, total: u32) -> u32 {
    if count == 0 || total == 0 { return 0; }
    let ratio_q12 = (count.saturating_mul(4096)) / total;
    if ratio_q12 == 0 { return 0; }
    let floor_log2 = integer_log2(ratio_q12);
    let denom = 1u32 << floor_log2;
    let frac = ratio_q12.saturating_sub(denom).saturating_mul(1000) / denom;
    let log2_milli = floor_log2.saturating_mul(1000).saturating_add(frac);
    (count.saturating_mul(log2_milli)) / total
}

#[inline(always)]
fn integer_log2(mut v: u32) -> u32 { let mut n = 0; while v > 1 { v >>= 1; n += 1; } n }

#[repr(align(64))]
pub struct SentinelCore { state: AtomicU8, ring: EventRing, entropy: EntropyWindow, score: u16 }

impl SentinelCore {
    pub const fn new() -> Self { Self { state: AtomicU8::new(State::Monitor as u8), ring: EventRing::new(), entropy: EntropyWindow::new(), score: 0 } }
    #[inline(always)] pub fn state(&self) -> State { State::from_raw(self.state.load(Ordering::Acquire)) }
    #[inline(always)] pub const fn score(&self) -> u16 { self.score }
    #[inline(always)] fn raise_state(&self, next: State) {
        let current = self.state.load(Ordering::Acquire);
        if next as u8 > current { self.state.store(next as u8, Ordering::Release); }
    }
    #[inline(always)]
    pub fn observe(&mut self, signal: Signal, offset: usize) {
        let severity = match signal { Signal::None => 0, Signal::ShellToken => 30, Signal::ProcSelfCmdline => 60, Signal::HighEntropy => 20, Signal::LowEntropy => 10, Signal::Tamper => 90, Signal::Debugger => 70, Signal::Root => 80, Signal::CertificateMismatch => 60 };
        self.score = self.score.saturating_add(severity as u16);
        self.ring.push(Event { signal, severity, offset: offset.min(u16::MAX as usize) as u16 });
        if self.score >= 100 { self.raise_state(State::Breached); } else if self.score >= 50 { self.raise_state(State::Anomalous); }
    }
    #[inline(always)]
    pub fn scan(&mut self, input: &[u8]) -> Decision {
        if self.state() == State::Breached { return Decision::Block; }
        let n = core::cmp::min(input.len(), MAX_INPUT);
        let data = &input[..n];
        self.entropy.load(data);
        self.scan_token(data, b"/system/bin/sh", Signal::ShellToken);
        self.scan_token(data, b"/system/bin/su", Signal::ShellToken);
        self.scan_token(data, b"/bin/sh", Signal::ShellToken);
        self.scan_token(data, b"busybox", Signal::ShellToken);
        if let Some(offset) = find_subslice(data, b"/proc/self/cmdline") { self.observe(Signal::ProcSelfCmdline, offset); }
        let entropy = self.entropy.shannon_milli_bits();
        if entropy > 7000 { self.observe(Signal::HighEntropy, 0); } else if n > 32 && entropy < 1500 { self.observe(Signal::LowEntropy, 0); }
        self.decision()
    }
    #[inline(always)] fn scan_token(&mut self, data: &[u8], token: &[u8], signal: Signal) { if let Some(offset) = find_subslice(data, token) { self.observe(signal, offset); } }
    #[inline(always)] pub const fn decision(&self) -> Decision { match State::from_raw(self.state.load(Ordering::Acquire)) { State::Monitor => Decision::Allow, State::Anomalous => Decision::Monitor, State::Breached => Decision::Block } }
    #[inline(always)] pub const fn event_count(&self) -> usize { self.ring.len() }
    #[inline(always)] pub fn event(&self, index: usize) -> Option<Event> { self.ring.get(index) }
}

#[inline]
pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    if needle.len() > haystack.len() { return None; }
    let last = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last {
        let mut j = 0;
        while j < needle.len() && haystack[i + j] == needle[j] { j += 1; }
        if j == needle.len() { return Some(i); }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn clean_input_allows() { let mut c = SentinelCore::new(); assert_eq!(c.scan(b"ordinary mobile telemetry"), Decision::Allow); }
    #[test] fn proc_cmdline_detected() { let mut c = SentinelCore::new(); c.scan(b"x/proc/self/cmdline"); assert_eq!(c.event_count(), 1); assert_eq!(c.event(0).unwrap().signal, Signal::ProcSelfCmdline); }
    #[test] fn high_risk_breaches() { let mut c = SentinelCore::new(); c.observe(Signal::Tamper, 0); c.observe(Signal::Root, 1); assert_eq!(c.state(), State::Breached); assert_eq!(c.decision(), Decision::Block); }
    #[test] fn breach_is_sticky() { let mut c = SentinelCore::new(); c.observe(Signal::Tamper, 0); c.observe(Signal::Root, 0); assert_eq!(c.scan(b"clean"), Decision::Block); }
    #[test] fn ring_is_bounded() { let mut c = SentinelCore::new(); for i in 0..(MAX_EVENTS + 10) { c.observe(Signal::None, i); } assert_eq!(c.event_count(), MAX_EVENTS); }
}
