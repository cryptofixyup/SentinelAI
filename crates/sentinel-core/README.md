# sentinel-core

Deterministic, allocation-free Rust security core for SentinelAI.

## Security boundary

- `#![no_std]`
- `#![forbid(unsafe_code)]`
- bounded input and event storage
- fixed-capacity ring buffer
- cache-line-aligned hot structures
- `AtomicU8` state machine with Acquire/Release ordering
- deterministic scoring
- bounded byte-token scanning
- fixed-window entropy analysis
- no networking or filesystem access

The crate is enforcement-only. Telemetry, intelligence, ML, and policy distribution remain outside the trusted enforcement core.

## Validation

```text
cargo test --workspace
```

Build and test this crate on an Android AArch64 target as part of the release gate.
