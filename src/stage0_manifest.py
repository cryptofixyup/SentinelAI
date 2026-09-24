"""Stage 0 canonical VCS change manifest primitives."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

SCHEMA_VERSION = "1"
RULESET_VERSION = "stage0-v1"


class Disposition(str, Enum):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"
    DEPENDENCY = "DEPENDENCY"
    GENERATED = "GENERATED"
    OVERSIZED = "OVERSIZED"
    NON_CODE = "NON_CODE"
    DELETED = "DELETED"
    REJECTED = "REJECTED"


class Reason(str, Enum):
    CODE_CHANGE = "code_change"
    MISLEADING_EXTENSION = "misleading_extension"
    DEPENDENCY = "dependency"
    GENERATED_ARTIFACT = "generated_artifact"
    OVERSIZED_ARTIFACT = "oversized_artifact"
    NON_CODE = "non_code"
    DELETED = "deleted"
    PATH_TRAVERSAL_ATTEMPT = "path_traversal_attempt"
    VCS_OBJECT_MISMATCH = "vcs_object_mismatch"
    VCS_OBJECT_MISSING = "vcs_object_missing"
    INVALID_PATH = "invalid_path"
    BINARY = "binary"


@dataclass(frozen=True)
class ChangeRecord:
    path: str
    change_type: str
    disposition: Disposition
    reason: Reason
    size_bytes: int
    is_binary: bool
    blob_object: str | None
    content_sha256: str | None
    rename_group_id: str | None = None

    def canonical(self) -> dict[str, object]:
        return {
            "path": self.path,
            "change_type": self.change_type,
            "disposition": self.disposition.value,
            "reason": self.reason.value,
            "size_bytes": self.size_bytes,
            "is_binary": self.is_binary,
            "blob_object": self.blob_object,
            "content_sha256": self.content_sha256,
            "rename_group_id": self.rename_group_id,
        }


@dataclass(frozen=True)
class Manifest:
    schema_version: str
    ruleset_version: str
    repository: str
    base_commit: str
    head_commit: str
    pr_number: int
    files: tuple[ChangeRecord, ...]
    manifest_sha256: str

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "ruleset_version": self.ruleset_version,
            "repository": self.repository,
            "base_commit": self.base_commit,
            "head_commit": self.head_commit,
            "pr_number": self.pr_number,
            "files": [record.canonical() for record in self.files],
        }

    def canonical_json(self) -> bytes:
        return canonical_json(self.payload())


def canonical_json(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rename_group_id(base_commit: str, head_commit: str, source_path: str, destination_path: str) -> str:
    payload = {
        "base_commit": base_commit,
        "head_commit": head_commit,
        "source_path": source_path,
        "destination_path": destination_path,
    }
    return sha256_hex(canonical_json(payload))


def freeze_manifest(*, repository: str, base_commit: str, head_commit: str, pr_number: int, files: Iterable[ChangeRecord]) -> Manifest:
    ordered = tuple(sorted(files, key=lambda record: (record.path, record.change_type, record.rename_group_id or "")))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "ruleset_version": RULESET_VERSION,
        "repository": repository,
        "base_commit": base_commit,
        "head_commit": head_commit,
        "pr_number": pr_number,
        "files": [record.canonical() for record in ordered],
    }
    digest = sha256_hex(canonical_json(payload))
    return Manifest(SCHEMA_VERSION, RULESET_VERSION, repository, base_commit, head_commit, pr_number, ordered, digest)


def safe_join(resolved_root: Path, candidate: str) -> Path:
    root = resolved_root.resolve(strict=True)
    candidate_path = (root / candidate).resolve(strict=False)
    try:
        candidate_path.relative_to(root)
    except ValueError as exc:
        raise ValueError("path_traversal_attempt") from exc
    return candidate_path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_binary_bytes(content: bytes) -> bool:
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return b"\x00" in content


def classify_path(path: str, content: bytes, *, generated: bool = False, dependency: bool = False, oversized: bool = False) -> tuple[Disposition, Reason]:
    if oversized:
        return Disposition.OVERSIZED, Reason.OVERSIZED_ARTIFACT
    if generated:
        return Disposition.GENERATED, Reason.GENERATED_ARTIFACT
    if dependency:
        return Disposition.DEPENDENCY, Reason.DEPENDENCY
    if is_binary_bytes(content):
        return Disposition.NON_CODE, Reason.BINARY
    suffix = PurePosixPath(path).suffix.lower()
    code_suffixes = {".py", ".rs", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".c", ".h", ".cpp", ".hpp", ".rb", ".sh"}
    text = content.decode("utf-8")
    executable_markers = ("#!/", "import ", "from ", "fn ", "def ", "class ", "function ", "const ", "let ", "use ")
    if suffix in code_suffixes:
        return Disposition.PRIMARY, Reason.CODE_CHANGE
    if any(marker in text for marker in executable_markers):
        return Disposition.SECONDARY, Reason.MISLEADING_EXTENSION
    return Disposition.NON_CODE, Reason.NON_CODE


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(f"blob {len(content)}\0".encode("ascii") + content).hexdigest()


def verify_head_binding(content: bytes, expected_blob_object: str, expected_content_sha256: str) -> None:
    if git_blob_sha(content) != expected_blob_object or sha256_hex(content) != expected_content_sha256:
        raise ValueError("vcs_object_mismatch")
