#!/usr/bin/env python3
"""P4.1-A JSON-RPC acquisition only."""

import argparse
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from p4.acquisition.jcs import canonical_json, sha256_json

SCHEMA_VERSION = "p4.1-a/v1"


def fail(message):
    raise SystemExit("P4.1-A ERROR: " + message)


def validate_case(case):
    if case.get("schema_version") != SCHEMA_VERSION:
        fail("unsupported schema_version")
    if case.get("status") != "FROZEN":
        fail("case must be explicitly FROZEN before acquisition")
    if not case.get("case_id") or not case.get("hypothesis"):
        fail("case_id and hypothesis are required")
    chains = case.get("chains")
    if not isinstance(chains, list) or len(chains) < 2:
        fail("at least two chains are required")
    for c in chains:
        br = c.get("block_range", {})
        if not isinstance(c.get("chain_id"), int) or not c.get("rpc_url_env"):
            fail("chain_id and rpc_url_env are required")
        if not isinstance(br.get("from"), int) or not isinstance(br.get("to"), int) or br["to"] < br["from"]:
            fail("invalid block range")
        if not c.get("requests") or not os.environ.get(c["rpc_url_env"]):
            fail("RPC source and requests are required")


def rpc(url, method, params, request_id):
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    req = urllib.request.Request(
        url,
        data=canonical_json(payload),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, dict):
        fail("RPC response is not an object")
    return payload, result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    case = json.loads(args.case.read_text())
    validate_case(case)

    if args.output.exists():
        fail("output already exists; capture directories are immutable")
    (args.output / "raw").mkdir(parents=True)

    captured_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    records = []
    request_id = 1

    for chain in case["chains"]:
        d = args.output / "raw" / chain["name"]
        d.mkdir()
        for i, spec in enumerate(chain["requests"]):
            method = spec["method"]
            params = spec.get("params", [])
            request_payload, response = rpc(
                os.environ[chain["rpc_url_env"]], method, params, request_id
            )
            request_id += 1
            record = {
                "chain": chain["name"],
                "chain_id": chain["chain_id"],
                "method": method,
                "params": params,
                "request_sha256": sha256_json(request_payload),
                "response_sha256": sha256_json(response),
                "block_range": chain["block_range"],
                "source_identifier": chain["rpc_url_env"],
                "captured_at": captured_at,
                "raw_response": response,
            }
            name = f"{i:04d}-{method}.json"
            (d / name).write_bytes(canonical_json(record))
            records.append({
                "chain": chain["name"],
                "file": str(Path("raw") / chain["name"] / name),
                "request_sha256": record["request_sha256"],
                "response_sha256": record["response_sha256"],
            })

    deterministic = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case["case_id"],
        "hash_algorithm": "SHA-256",
        "canonicalization": "RFC 8785 JCS",
        "records": records,
    }
    manifest = {
        **deterministic,
        "captured_at": captured_at,
        "deterministic_dataset_sha256": sha256_json(deterministic),
    }
    (args.output / "manifest.json").write_bytes(canonical_json(manifest))
    (args.output / "SHA256SUMS").write_text(
        "".join(f"{r['response_sha256']}  {r['file']}\n" for r in records)
    )
    print(json.dumps({
        "status": "CAPTURED",
        "case_id": case["case_id"],
        "records": len(records),
        "canonicalization": "RFC 8785 JCS",
        "deterministic_dataset_sha256": manifest["deterministic_dataset_sha256"],
    }, indent=2))


if __name__ == "__main__":
    main()
