from __future__ import annotations

import argparse
import json

from .collector import collect_safe_state
from .policy import evaluate


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelAI deterministic custody policy validator")
    parser.add_argument("--state", help="JSON state fixture to evaluate")
    parser.add_argument("--rpc-url", help="JSON-RPC URL for live Safe collection")
    parser.add_argument("--safe", help="Safe address")
    parser.add_argument("--chain-id", type=int)
    args = parser.parse_args()

    if bool(args.state) == bool(args.rpc_url):
        parser.error("provide exactly one of --state or --rpc-url")

    if args.state:
        with open(args.state, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    else:
        if not args.safe:
            parser.error("--safe is required with --rpc-url")
        state = collect_safe_state(args.rpc_url, args.safe, args.chain_id).as_dict()

    result = evaluate(state)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] != "BLOCK" else 2


if __name__ == "__main__":
    raise SystemExit(main())
