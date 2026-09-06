"""Stage 1 deterministic evidence-construction boundary.

Stage 1 verifies a Stage 0 manifest, reads immutable Git objects, parses
PRIMARY/DELETED source material structurally, and emits a deterministic
Evidence Manifest. It does not make vulnerability determinations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from tree_sitter import Language, Parser
import tree_sitter_rust

from .stage0_manifest import Disposition, Manifest, Reason, canonical_json, sha256_hex

STAGE1_SCHEMA_VERSION = "1.0.0"
STAGE1_RULESET_VERSION = "stage1-v1"
DEFAULT_MAX_BLOCKS = 128
DEFAULT_MAX_BLOCK_BYTES = 16 * 1024
DEFAULT_MAX_REFERENCED_NODES = 256
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024


class Stage1Error(ValueError):
    pass


class EvidenceType(str, Enum):
    MODIFIED_FUNCTION = "MODIFIED_FUNCTION"
    MODIFIED_METHOD = "MODIFIED_METHOD"
    MODIFIED_TYPE = "MODIFIED_TYPE"
    SECURITY_SENSITIVE_DECLARATION = "SECURITY_SENSITIVE_DECLARATION"
    CALL = "CALL"
    CONDITION = "CONDITION"
    RETURN = "RETURN"
    AUTHORIZATION_CHECK = "AUTHORIZATION_CHECK"
    INPUT_BOUNDARY = "INPUT_BOUNDARY"
    DATABASE_OPERATION = "DATABASE_OPERATION"
    NETWORK_OPERATION = "NETWORK_OPERATION"
    CRYPTO_OPERATION = "CRYPTO_OPERATION"
    DELETED_NODE = "DELETED_NODE"


@dataclass(frozen=True)
class AstNodeRef:
    node_type: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int


@dataclass(frozen=True)
class EvidenceBlock:
    id: str
    evidence_type: EvidenceType
    path: str
    commit: str
    object_id: str
    content_sha256: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    node_type: str
    content: str | None = None

    def canonical(self) -> dict[str, object]:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "path": self.path,
            "commit": self.commit,
            "object_id": self.object_id,
            "content_sha256": self.content_sha256,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "node_type": self.node_type,
            "content": self.content,
        }


@dataclass(frozen=True)
class EvidenceManifest:
    schema_version: str
    ruleset_version: str
    stage0_sha256: str
    repository: str
    base_commit: str
    head_commit: str
    parser: Mapping[str, str]
    evidence_blocks: tuple[EvidenceBlock, ...]
    incomplete: bool
    stage1_sha256: str

    def payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "ruleset_version": self.ruleset_version,
            "stage0_sha256": self.stage0_sha256,
            "repository": self.repository,
            "base_commit": self.base_commit,
            "head_commit": self.head_commit,
            "parser": dict(self.parser),
            "evidence_blocks": [block.canonical() for block in self.evidence_blocks],
            "incomplete": self.incomplete,
        }

    def canonical_json(self) -> bytes:
        return canonical_json(self.payload())


def _constant_time_equal_hex(left: str, right: str) -> bool:
    try:
        return hmac.compare_digest(bytes.fromhex(left), bytes.fromhex(right))
    except ValueError:
        return False


def verify_stage0_manifest(raw_manifest: Mapping[str, Any]) -> Manifest:
    """Verify the Stage 0 commitment before any evidence extraction."""
    required = {
        "schema_version", "ruleset_version", "repository", "base_commit",
        "head_commit", "pr_number", "files", "manifest_sha256",
    }
    if set(raw_manifest) != required:
        raise Stage1Error("stage0_schema_mismatch")
    if not isinstance(raw_manifest["manifest_sha256"], str):
        raise Stage1Error("stage0_hash_malformed")

    payload = {key: raw_manifest[key] for key in required if key != "manifest_sha256"}
    calculated = sha256_hex(canonical_json(payload))
    if not _constant_time_equal_hex(calculated, raw_manifest["manifest_sha256"]):
        raise Stage1Error("stage0_integrity_mismatch")

    try:
        records = []
        for item in raw_manifest["files"]:
            if set(item) != {
                "path", "change_type", "disposition", "reason", "size_bytes",
                "is_binary", "blob_object", "content_sha256",
            }:
                raise Stage1Error("stage0_schema_mismatch")
            records.append(item)
        parsed = tuple(_change_record_from_mapping(item) for item in records)
        manifest = Manifest(
            schema_version=str(raw_manifest["schema_version"]),
            ruleset_version=str(raw_manifest["ruleset_version"]),
            repository=str(raw_manifest["repository"]),
            base_commit=str(raw_manifest["base_commit"]),
            head_commit=str(raw_manifest["head_commit"]),
            pr_number=int(raw_manifest["pr_number"]),
            files=parsed,
            manifest_sha256=str(raw_manifest["manifest_sha256"]),
        )
    except (TypeError, ValueError) as exc:
        raise Stage1Error("stage0_schema_mismatch") from exc

    if manifest.schema_version != "1" or manifest.ruleset_version != "stage0-v1":
        raise Stage1Error("stage0_schema_mismatch")
    return manifest


def _change_record_from_mapping(item: Mapping[str, Any]):
    from .stage0_manifest import ChangeRecord
    return ChangeRecord(
        path=str(item["path"]),
        change_type=str(item["change_type"]),
        disposition=Disposition(str(item["disposition"])),
        reason=Reason(str(item["reason"])),
        size_bytes=int(item["size_bytes"]),
        is_binary=bool(item["is_binary"]),
        blob_object=item["blob_object"],
        content_sha256=item["content_sha256"],
    )


class GitObjectReader:
    """Read immutable objects from the repository's Git object database."""

    def __init__(self, repository_root: str):
        self.repository_root = repository_root

    def verify_commit_available(self, commit: str) -> None:
        self._run("git", "cat-file", "-e", f"{commit}^{{commit}}")

    def read_blob(self, object_id: str) -> bytes:
        output = self._run("git", "cat-file", "blob", object_id)
        return output

    def _run(self, *args: str) -> bytes:
        try:
            result = subprocess.run(
                args,
                cwd=self.repository_root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise Stage1Error("vcs_object_missing") from exc
        return result.stdout


def verify_manifest_objects(manifest: Manifest, reader: GitObjectReader) -> None:
    reader.verify_commit_available(manifest.base_commit)
    reader.verify_commit_available(manifest.head_commit)
    for record in manifest.files:
        if record.disposition in {Disposition.PRIMARY, Disposition.DELETED, Disposition.SECONDARY}:
            if not record.blob_object or not record.content_sha256:
                raise Stage1Error("vcs_object_missing")
            content = reader.read_blob(record.blob_object)
            if sha256_hex(content) != record.content_sha256:
                raise Stage1Error("vcs_object_mismatch")


def rust_parser() -> tuple[Parser, dict[str, str]]:
    language = Language(tree_sitter_rust.language())
    parser = Parser(language)
    metadata = {
        "name": "tree-sitter",
        "version": "0.25.x",
        "grammar": "tree-sitter-rust",
        "grammar_version": "0.24.x",
    }
    return parser, metadata


def _node_ref(node: Any) -> AstNodeRef:
    return AstNodeRef(
        node_type=node.type,
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
    )


def parse_ast(content: bytes) -> tuple[AstNodeRef, ...]:
    parser, _ = rust_parser()
    tree = parser.parse(content)
    refs: list[AstNodeRef] = []

    def visit(node: Any) -> None:
        refs.append(_node_ref(node))
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return tuple(refs)


def _is_candidate(node: AstNodeRef) -> EvidenceType | None:
    mapping = {
        "function_item": EvidenceType.MODIFIED_FUNCTION,
        "struct_item": EvidenceType.MODIFIED_TYPE,
        "enum_item": EvidenceType.MODIFIED_TYPE,
        "trait_item": EvidenceType.MODIFIED_TYPE,
        "impl_item": EvidenceType.MODIFIED_TYPE,
        "call_expression": EvidenceType.CALL,
        "if_expression": EvidenceType.CONDITION,
        "match_expression": EvidenceType.CONDITION,
        "return_expression": EvidenceType.RETURN,
    }
    return mapping.get(node.node_type)


def deterministic_evidence_id(index: int) -> str:
    if index < 0:
        raise Stage1Error("invalid_evidence_index")
    return f"E-{index + 1:06d}"


def build_evidence_blocks(
    *,
    manifest: Manifest,
    reader: GitObjectReader,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
    max_referenced_nodes: int = DEFAULT_MAX_REFERENCED_NODES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> tuple[tuple[EvidenceBlock, ...], bool]:
    if min(max_blocks, max_block_bytes, max_referenced_nodes, max_total_bytes) <= 0:
        raise Stage1Error("invalid_evidence_limits")

    candidates: list[tuple[str, str, str, bytes, AstNodeRef, EvidenceType]] = []
    for record in manifest.files:
        if record.disposition not in {Disposition.PRIMARY, Disposition.DELETED}:
            continue
        if not record.blob_object or not record.content_sha256:
            raise Stage1Error("vcs_object_missing")
        content = reader.read_blob(record.blob_object)
        if sha256_hex(content) != record.content_sha256:
            raise Stage1Error("vcs_object_mismatch")
        refs = parse_ast(content)
        for ref in refs:
            evidence_type = _is_candidate(ref)
            if evidence_type is not None:
                candidates.append((record.path, record.change_type, record.blob_object, content, ref, evidence_type))

    candidates.sort(key=lambda item: (item[0], item[4].start_byte, item[4].end_byte, item[4].node_type, item[5].value))
    incomplete = len(candidates) > max_blocks
    blocks: list[EvidenceBlock] = []
    total_bytes = 0
    for candidate in candidates[:max_blocks]:
        path, change_type, object_id, content, ref, evidence_type = candidate
        block_bytes = content[ref.start_byte:ref.end_byte]
        if len(block_bytes) > max_block_bytes or total_bytes + len(block_bytes) > max_total_bytes:
            incomplete = True
            break
        if len(blocks) >= max_referenced_nodes:
            incomplete = True
            break
        text = block_bytes.decode("utf-8", errors="strict")
        if change_type == "deleted" or evidence_type in {EvidenceType.MODIFIED_FUNCTION, EvidenceType.MODIFIED_TYPE} and change_type == "renamed_from":
            evidence_type = EvidenceType.DELETED_NODE if change_type == "deleted" else evidence_type
        blocks.append(EvidenceBlock(
            id=deterministic_evidence_id(len(blocks)),
            evidence_type=evidence_type,
            path=path,
            commit=manifest.base_commit if change_type in {"deleted", "renamed_from"} else manifest.head_commit,
            object_id=object_id,
            content_sha256=sha256_hex(content),
            start_byte=ref.start_byte,
            end_byte=ref.end_byte,
            start_line=ref.start_line,
            end_line=ref.end_line,
            node_type=ref.node_type,
            content=text,
        ))
        total_bytes += len(block_bytes)

    return tuple(blocks), incomplete


def build_evidence_manifest(
    raw_stage0_manifest: Mapping[str, Any],
    repository_root: str,
    *,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
    max_referenced_nodes: int = DEFAULT_MAX_REFERENCED_NODES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> EvidenceManifest:
    manifest = verify_stage0_manifest(raw_stage0_manifest)
    reader = GitObjectReader(repository_root)
    verify_manifest_objects(manifest, reader)
    blocks, incomplete = build_evidence_blocks(
        manifest=manifest,
        reader=reader,
        max_blocks=max_blocks,
        max_block_bytes=max_block_bytes,
        max_referenced_nodes=max_referenced_nodes,
        max_total_bytes=max_total_bytes,
    )
    payload = {
        "schema_version": STAGE1_SCHEMA_VERSION,
        "ruleset_version": STAGE1_RULESET_VERSION,
        "stage0_sha256": manifest.manifest_sha256,
        "repository": manifest.repository,
        "base_commit": manifest.base_commit,
        "head_commit": manifest.head_commit,
        "parser": rust_parser()[1],
        "evidence_blocks": [block.canonical() for block in blocks],
        "incomplete": incomplete,
    }
    digest = sha256_hex(canonical_json(payload))
    return EvidenceManifest(
        schema_version=STAGE1_SCHEMA_VERSION,
        ruleset_version=STAGE1_RULESET_VERSION,
        stage0_sha256=manifest.manifest_sha256,
        repository=manifest.repository,
        base_commit=manifest.base_commit,
        head_commit=manifest.head_commit,
        parser=rust_parser()[1],
        evidence_blocks=blocks,
        incomplete=incomplete,
        stage1_sha256=digest,
    )
