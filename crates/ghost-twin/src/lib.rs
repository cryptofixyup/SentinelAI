#![forbid(unsafe_code)]

use sentinel_core::{Decision, SentinelCore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TradeIntent {
    pub chain_id: u64,
    pub max_slippage_bps: u16,
    pub amount_units: u64,
    pub live_requested: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaperFill {
    pub filled: bool,
    pub amount_units: u64,
    pub slippage_bps: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Shadow,
    Deny,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionGate {
    pub allow_live: bool,
}

impl ExecutionGate {
    pub const fn denied() -> Self {
        Self { allow_live: false }
    }

    pub const fn live_enabled() -> Self {
        Self { allow_live: true }
    }

    #[inline(always)]
    pub const fn decide(&self, risk: Decision, live_requested: bool) -> GateDecision {
        match risk {
            Decision::Block => GateDecision::Deny,
            Decision::Allow if live_requested && self.allow_live => GateDecision::Live,
            Decision::Monitor => GateDecision::Shadow,
            Decision::Allow => GateDecision::Shadow,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwinEngine {
    pub gate: ExecutionGate,
}

impl TwinEngine {
    pub const fn new(gate: ExecutionGate) -> Self {
        Self { gate }
    }

    #[inline(always)]
    pub fn evaluate(
        &self,
        core: &mut SentinelCore,
        intent: TradeIntent,
        payload: &[u8],
    ) -> (Decision, GateDecision, PaperFill) {
        let risk = core.scan(payload);
        let gate = self.gate.decide(risk, intent.live_requested);
        let fill = match gate {
            GateDecision::Deny => PaperFill {
                filled: false,
                amount_units: 0,
                slippage_bps: 0,
            },
            GateDecision::Shadow | GateDecision::Live => PaperFill {
                filled: true,
                amount_units: intent.amount_units,
                slippage_bps: intent.max_slippage_bps,
            },
        };
        (risk, gate, fill)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_is_disabled_by_default() {
        let engine = TwinEngine::new(ExecutionGate::denied());
        let mut core = SentinelCore::new();
        let intent = TradeIntent {
            chain_id: 1,
            max_slippage_bps: 50,
            amount_units: 100,
            live_requested: true,
        };
        let (_, gate, fill) = engine.evaluate(&mut core, intent, b"clean");
        assert_eq!(gate, GateDecision::Shadow);
        assert!(fill.filled);
    }

    #[test]
    fn monitor_can_never_go_live() {
        let engine = TwinEngine::new(ExecutionGate::live_enabled());
        let mut core = SentinelCore::new();
        core.observe(sentinel_core::Signal::Debugger, 0);
        let intent = TradeIntent {
            chain_id: 1,
            max_slippage_bps: 50,
            amount_units: 100,
            live_requested: true,
        };
        let (risk, gate, fill) = engine.evaluate(&mut core, intent, b"clean");
        assert_eq!(risk, Decision::Monitor);
        assert_eq!(gate, GateDecision::Shadow);
        assert!(fill.filled);
    }

    #[test]
    fn breach_denies_even_when_live_enabled() {
        let engine = TwinEngine::new(ExecutionGate::live_enabled());
        let mut core = SentinelCore::new();
        core.observe(sentinel_core::Signal::Tamper, 0);
        core.observe(sentinel_core::Signal::Root, 0);
        let intent = TradeIntent {
            chain_id: 1,
            max_slippage_bps: 50,
            amount_units: 100,
            live_requested: true,
        };
        let (risk, gate, fill) = engine.evaluate(&mut core, intent, b"clean");
        assert_eq!(risk, Decision::Block);
        assert_eq!(gate, GateDecision::Deny);
        assert!(!fill.filled);
    }
}
