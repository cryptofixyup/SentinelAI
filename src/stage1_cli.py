"""Stage 1 CLI: verify a Stage 0 manifest and emit deterministic evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage1_evidence import build_evidence_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic Stage 1 evidence from a Stage 0 manifest")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("repository", type=Path)
    args = parser.parse_args()
    raw = json.loads(args.manifest.read_text(encoding="utf-8"))
    evidence = build_evidence_manifest(raw, str(args.repository))
    output = evidence.payload()
    output["stage1_sha256"] = evidence.stage1_sha256
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
