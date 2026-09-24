"""Deterministic Stage 1 evidence-construction boundary.

Stage 1 verifies the Stage 0 commitment, reads source bytes from the Git
object database, parses Rust structurally, and emits a committed evidence
payload. It never trusts the working tree for source provenance and never
makes security conclusions.
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess
from dataclasses import dataclass
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Mapping

from tree_sitter import Language, Parser
import tree_sitter_rust

from .stage0_manifest import ChangeRecord, Disposition, Manifest, Reason, canonical_json, sha256_hex

STAGE1_SCHEMA_VERSION = "1.0.0"
STAGE1_RULESET_VERSION = "stage1-v1"
DEFAULT_MAX_BLOCKS = 128
DEFAULT_MAX_BLOCK_BYTES = 16 * 1024
DEFAULT_MAX_REFERENCED_NODES = 256
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024


class Stage1Error(ValueError):
    """Fail-closed Stage 1 boundary error."""


class EvidenceType(str, Enum):
    MODIFIED_FUNCTION = "MODIFIED_FUNCTION"
    MODIFIED_METHOD = "MODIFIED_METHOD"
    MODIFIED_TYPE = "MODIFIED_TYPE"
    CALL = "CALL"
    CONDITION = "CONDITION"
    RETURN = "RETURN"
    DELETED_NODE = "DELETED_NODE"


@dataclass(frozen=True)
class AstNodeRef:
    node_type: str
    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass(frozen=True)
class EvidenceBlock:
    id: str
    evidence_type: EvidenceType
    path: str
    commit: str
    object_id: str
    source_sha256: str
    content_sha256: str
    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    node_type: str
    content: str

    def canonical(self) -> dict[str, object]:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "path": self.path,
            "commit": self.commit,
            "object_id": self.object_id,
            "source_sha256": self.source_sha256,
            "content_sha256": self.content_sha256,
            "start_byte": self.start_byte,
            "end_byte": self.end_byte,
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
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
    parser: tuple[tuple[str, str], ...]
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
    """Verify the exact Stage 0 canonical commitment before extraction."""
    required = {
        "schema_version", "ruleset_version", "repository", "base_commit",
        "head_commit", "pr_number", "files", "manifest_sha256",
    }
    if set(raw_manifest) != required or not isinstance(raw_manifest.get("manifest_sha256"), str):
        raise Stage1Error("stage0_schema_mismatch")
    if not isinstance(raw_manifest.get("files"), list):
        raise Stage1Error("stage0_schema_mismatch")

    payload = {key: raw_manifest[key] for key in raw_manifest if key != "manifest_sha256"}
    calculated = sha256_hex(canonical_json(payload))
    if not _constant_time_equal_hex(calculated, raw_manifest["manifest_sha256"]):
        raise Stage1Error("stage0_integrity_mismatch")

    expected_fields = {
        "path", "change_type", "disposition", "reason", "size_bytes",
        "is_binary", "blob_object", "content_sha256", "rename_group_id",
    }
    records: list[ChangeRecord] = []
    try:
        for item in raw_manifest["files"]:
            if not isinstance(item, Mapping) or set(item) != expected_fields:
                raise Stage1Error("stage0_schema_mismatch")
            records.append(_change_record_from_mapping(item))
        manifest = Manifest(
            schema_version=str(raw_manifest["schema_version"]),
            ruleset_version=str(raw_manifest["ruleset_version"]),
            repository=str(raw_manifest["repository"]),
            base_commit=str(raw_manifest["base_commit"]),
            head_commit=str(raw_manifest["head_commit"]),
            pr_number=int(raw_manifest["pr_number"]),
            files=tuple(records),
            manifest_sha256=raw_manifest["manifest_sha256"],
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, Stage1Error):
            raise
        raise Stage1Error("stage0_schema_mismatch") from exc

    if manifest.schema_version != "1" or manifest.ruleset_version != "stage0-v1":
        raise Stage1Error("stage0_schema_mismatch")
    return manifest


def _change_record_from_mapping(item: Mapping[str, Any]) -> ChangeRecord:
    try:
        return ChangeRecord(
            path=str(item["path"]),
            change_type=str(item["change_type"]),
            disposition=Disposition(str(item["disposition"])),
            reason=Reason(str(item["reason"])),
            size_bytes=int(item["size_bytes"]),
            is_binary=bool(item["is_binary"]),
            blob_object=item["blob_object"],
            content_sha256=item["content_sha256"],
            rename_group_id=item["rename_group_id"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise Stage1Error("stage0_schema_mismatch") from exc


class GitObjectReader:
    """Read and verify immutable Git objects; never reads source from the worktree."""

    def __init__(self, repository_root: str):
        self.repository_root = repository_root

    def verify_commit_available(self, commit: str) -> None:
        self._run("git", "cat-file", "-e", f"{commit}^{{commit}}")

    def resolve_path_blob(self, commit: str, path: str) -> str:
        try:
            output = self._run("git", "rev-parse", f"{commit}:{path}")
            object_id = output.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise Stage1Error("vcs_object_missing") from exc
        if len(object_id) != 40 or any(ch not in "0123456789abcdef" for ch in object_id):
            raise Stage1Error("vcs_object_missing")
        return object_id

    def read_blob(self, object_id: str) -> bytes:
        return self._run("git", "cat-file", "blob", object_id)

    def read_bound_blob(self, *, commit: str, path: str, expected_object: str, expected_sha256: str) -> bytes:
        resolved = self.resolve_path_blob(commit, path)
        if resolved != expected_object:
            raise Stage1Error("vcs_object_mismatch")
        content = self.read_blob(expected_object)
        if sha256_hex(content) != expected_sha256:
            raise Stage1Error("vcs_object_mismatch")
        return content

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


def _record_commit(record: ChangeRecord, manifest: Manifest) -> str:
    if record.change_type in {"deleted", "renamed_from", "copied_from"} or record.disposition is Disposition.DELETED:
        return manifest.base_commit
    return manifest.head_commit


def verify_manifest_objects(manifest: Manifest, reader: GitObjectReader) -> None:
    reader.verify_commit_available(manifest.base_commit)
    reader.verify_commit_available(manifest.head_commit)
    for record in manifest.files:
        if not record.blob_object or not record.content_sha256:
            if record.disposition in {Disposition.PRIMARY, Disposition.DELETED}:
                raise Stage1Error("vcs_object_missing")
            continue
        commit = _record_commit(record, manifest)
        content = reader.read_bound_blob(
            commit=commit,
            path=record.path,
            expected_object=record.blob_object,
            expected_sha256=record.content_sha256,
        )
        if len(content) != record.size_bytes:
            raise Stage1Error("vcs_object_mismatch")


def rust_parser() -> tuple[Parser, tuple[tuple[str, str], ...]]:
    language = Language(tree_sitter_rust.language())
    parser = Parser(language)
    try:
        binding_version = version("tree-sitter")
    except PackageNotFoundError as exc:
        raise Stage1Error("parser_metadata_unavailable") from exc
    try:
        grammar_version = version("tree-sitter-rust")
    except PackageNotFoundError as exc:
        raise Stage1Error("parser_metadata_unavailable") from exc
    metadata = (
        ("name", "tree-sitter"),
        ("binding_version", binding_version),
        ("grammar", "tree-sitter-rust"),
        ("grammar_version", grammar_version),
    )
    return parser, metadata


def _node_ref(node: Any) -> AstNodeRef:
    return AstNodeRef(
        node_type=node.type,
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        start_line=node.start_point[0] + 1,
        start_column=node.start_point[1],
        end_line=node.end_point[0] + 1,
        end_column=node.end_point[1],
    )


def parse_ast(content: bytes) -> tuple[AstNodeRef, ...]:
    parser, _ = rust_parser()
    tree = parser.parse(content)
    if tree.root_node.has_error:
        raise Stage1Error("parse_error")

    refs: list[AstNodeRef] = []

    def visit(node: Any) -> None:
        refs.append(_node_ref(node))
        for child in node.children:
            visit(child)

    visit(tree.root_node)
    return tuple(refs)


def _is_candidate(node: AstNodeRef) -> EvidenceType | None:
    return {
        "function_item": EvidenceType.MODIFIED_FUNCTION,
        "struct_item": EvidenceType.MODIFIED_TYPE,
        "enum_item": EvidenceType.MODIFIED_TYPE,
        "trait_item": EvidenceType.MODIFIED_TYPE,
        "impl_item": EvidenceType.MODIFIED_TYPE,
        "call_expression": EvidenceType.CALL,
        "if_expression": EvidenceType.CONDITION,
        "match_expression": EvidenceType.CONDITION,
        "return_expression": EvidenceType.RETURN,
    }.get(node.node_type)


def evidence_id(*, source_sha256: str, file: str, commit: str, object_id: str, node: AstNodeRef, evidence_type: EvidenceType) -> str:
    hasher = hashlib.sha256()
    fields = (
        b"stage1-evidence-v2\0",
        source_sha256.encode("ascii"), b"\0",
        file.encode("utf-8"), b"\0",
        commit.encode("ascii"), b"\0",
        object_id.encode("ascii"), b"\0",
        evidence_type.value.encode("ascii"), b"\0",
        node.node_type.encode("utf-8"), b"\0",
        node.start_byte.to_bytes(8, "little"),
        node.end_byte.to_bytes(8, "little"),
    )
    for field in fields:
        hasher.update(field)
    return f"E-{hasher.hexdigest()}"


def deterministic_evidence_id(index: int) -> str:
    """Legacy test helper; not used for authoritative evidence identity."""
    if index < 0:
        raise Stage1Error("invalid_evidence_index")
    return f"E-{index + 1:06d}"


def build_evidence_blocks(*, manifest: Manifest, reader: GitObjectReader, max_blocks: int = DEFAULT_MAX_BLOCKS, max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES, max_referenced_nodes: int = DEFAULT_MAX_REFERENCED_NODES, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES) -> tuple[tuple[EvidenceBlock, ...], bool]:
    if min(max_blocks, max_block_bytes, max_referenced_nodes, max_total_bytes) <= 0:
        raise Stage1Error("invalid_evidence_limits")

    candidates: list[tuple[str, str, str, str, bytes, AstNodeRef, EvidenceType]] = []
    for record in manifest.files:
        if record.disposition not in {Disposition.PRIMARY, Disposition.DELETED}:
            continue
        if not record.blob_object or not record.content_sha256:
            raise Stage1Error("vcs_object_missing")
        commit = _record_commit(record, manifest)
        content = reader.read_bound_blob(
            commit=commit,
            path=record.path,
            expected_object=record.blob_object,
            expected_sha256=record.content_sha256,
        )
        refs = parse_ast(content)
        for ref in refs:
            evidence_type = _is_candidate(ref)
            if evidence_type is not None:
                candidates.append((record.path, record.change_type, commit, record.blob_object, content, ref, evidence_type))

    candidates.sort(key=lambda item: (item[0], item[2], item[4][item[5].start_byte:item[5].end_byte], item[5].start_byte, item[5].end_byte, item[5].node_type, item[6].value, item[3]))
    incomplete = len(candidates) > max_blocks
    candidates = candidates[:max_blocks]

    blocks: list[EvidenceBlock] = []
    total_bytes = 0
    for path, change_type, commit, object_id, content, ref, evidence_type in candidates:
        if len(blocks) >= max_referenced_nodes:
            incomplete = True
            break
        if ref.start_byte > ref.end_byte or ref.end_byte > len(content):
            raise Stage1Error("invalid_ast_span")
        block_bytes = content[ref.start_byte:ref.end_byte]
        if len(block_bytes) > max_block_bytes or total_bytes + len(block_bytes) > max_total_bytes:
            incomplete = True
            break
        try:
            text = block_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Stage1Error("source_not_utf8") from exc
        source_hash = sha256_hex(content)
        block_hash = sha256_hex(block_bytes)
        if change_type in {"deleted", "renamed_from"}:
            evidence_type = EvidenceType.DELETED_NODE
        blocks.append(EvidenceBlock(
            id=evidence_id(source_sha256=source_hash, file=path, commit=commit, object_id=object_id, node=ref, evidence_type=evidence_type),
            evidence_type=evidence_type,
            path=path,
            commit=commit,
            object_id=object_id,
            source_sha256=source_hash,
            content_sha256=block_hash,
            start_byte=ref.start_byte,
            end_byte=ref.end_byte,
            start_line=ref.start_line,
            start_column=ref.start_column,
            end_line=ref.end_line,
            end_column=ref.end_column,
            node_type=ref.node_type,
            content=text,
        ))
        total_bytes += len(block_bytes)

    ids = [block.id for block in blocks]
    if len(ids) != len(set(ids)):
        raise Stage1Error("duplicate_evidence_id")
    return tuple(blocks), incomplete


def build_evidence_manifest(raw_stage0_manifest: Mapping[str, Any], repository_root: str, *, max_blocks: int = DEFAULT_MAX_BLOCKS, max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES, max_referenced_nodes: int = DEFAULT_MAX_REFERENCED_NODES, max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES) -> EvidenceManifest:
    manifest = verify_stage0_manifest(raw_stage0_manifest)
    reader = GitObjectReader(repository_root)
    verify_manifest_objects(manifest, reader)
    blocks, incomplete = build_evidence_blocks(manifest=manifest, reader=reader, max_blocks=max_blocks, max_block_bytes=max_block_bytes, max_referenced_nodes=max_referenced_nodes, max_total_bytes=max_total_bytes)
    parser_metadata = rust_parser()[1]
    payload = {
        "schema_version": STAGE1_SCHEMA_VERSION,
        "ruleset_version": STAGE1_RULESET_VERSION,
        "stage0_sha256": manifest.manifest_sha256,
        "repository": manifest.repository,
        "base_commit": manifest.base_commit,
        "head_commit": manifest.head_commit,
        "parser": dict(parser_metadata),
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
        parser=parser_metadata,
        evidence_blocks=blocks,
        incomplete=incomplete,
        stage1_sha256=digest,
    )
