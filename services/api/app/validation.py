from __future__ import annotations

import re

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def normalize_address(value: str) -> str:
    if not ADDRESS_RE.fullmatch(value):
        raise ValueError("invalid Ethereum address")
    return value.lower()
