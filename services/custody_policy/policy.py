from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .scoring import evaluate_custody

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "custody-policy.schema.json"
POLICY_PATH = ROOT / "custody-policy.yaml"


def load_policy(path: str | Path = POLICY_PATH) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        policy = yaml.safe_load(handle)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(f"{'.'.join(map(str, e.path))}: {e.message}" for e in errors)
        raise ValueError(f"invalid custody policy: {details}")
    return policy


def evaluate(state: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    return evaluate_custody(state, policy or load_policy())
