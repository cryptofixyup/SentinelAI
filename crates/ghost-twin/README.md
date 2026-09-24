# ghost-twin

Isolated deterministic execution boundary for SentinelAI.

```text
Ghost -> TradeIntent -> Sentinel risk boundary -> Twin paper/shadow fill
                                      \\-> ExecutionGate -> live only when allow_live=true
```

The crate contains no key management or signing and performs no external network operations. A future Jito adapter should accept already-signed transactions at an outer integration boundary.

Live execution is disabled by default.
