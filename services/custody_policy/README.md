# Custody policy package

This package provides deterministic, fail-closed custody validation.

## Components

- `custody-policy.yaml`: policy configuration.
- `custody-policy.schema.json`: JSON Schema validation.
- `scoring.py`: deterministic signer and transaction risk scoring.
- `collector.py`: read-only Safe state collection over JSON-RPC.
- `policy.py`: policy loading and schema validation.
- `cli.py`: local fixture or live RPC evaluation.

The collector is read-only and never accepts private keys or signing material.
