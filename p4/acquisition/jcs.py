"""RFC 8785 JSON Canonicalization Scheme boundary for P4.1-A."""

from __future__ import annotations

import rfc8785


def canonical_json(value: object) -> bytes:
    """Return RFC 8785/JCS canonical UTF-8 JSON bytes."""
    return rfc8785.dumps(value)


def sha256_json(value: object) -> str:
    """Return SHA-256 over RFC 8785/JCS canonical bytes."""
    import hashlib

    return hashlib.sha256(canonical_json(value)).hexdigest()
