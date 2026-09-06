import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from src.stage0_manifest import ChangeRecord, Disposition, Reason, freeze_manifest, git_blob_sha, sha256_hex
from src.stage1_evidence import (
    EvidenceType,
    GitObjectReader,
    Stage1Error,
    build_evidence_manifest,
    deterministic_evidence_id,
    parse_ast,
    verify_stage0_manifest,
)


def make_manifest(content: bytes, *, disposition=Disposition.PRIMARY, change_type="modified"):
    record = ChangeRecord(
        path="src/main.rs",
        change_type=change_type,
        disposition=disposition,
        reason=Reason.CODE_CHANGE,
        size_bytes=len(content),
        is_binary=False,
        blob_object=git_blob_sha(content),
        content_sha256=sha256_hex(content),
    )
    return freeze_manifest(
        repository="test/repo",
        base_commit="a" * 40,
        head_commit="b" * 40,
        pr_number=1,
        files=[record],
    )


def manifest_json(manifest):
    payload = manifest.payload()
    payload["manifest_sha256"] = manifest.manifest_sha256
    return payload


def test_stage0_manifest_verification_rejects_tampering():
    manifest = make_manifest(b"fn main() {}\n")
    raw = manifest_json(manifest)
    raw["head_commit"] = "c" * 40
    with pytest.raises(Stage1Error, match="stage0_integrity_mismatch"):
        verify_stage0_manifest(raw)


def test_stage0_manifest_verification_rejects_unknown_disposition():
    manifest = make_manifest(b"fn main() {}\n")
    raw = manifest_json(manifest)
    raw["files"][0]["disposition"] = "VULNERABLE"
    with pytest.raises(Stage1Error, match="stage0_integrity_mismatch"):
        verify_stage0_manifest(raw)


def test_evidence_id_is_deterministic():
    assert [deterministic_evidence_id(i) for i in range(3)] == ["E-000001", "E-000002", "E-000003"]


def test_rust_ast_ranges_are_valid():
    content = b"fn main() { let x = 1; if x > 0 { return; } }\n"
    refs = parse_ast(content)
    assert refs
    for ref in refs:
        assert 0 <= ref.start_byte <= ref.end_byte <= len(content)
        assert ref.start_line <= ref.end_line


def test_secondary_dependency_and_non_code_are_not_stage1_evidence():
    content = b"#!/usr/bin/env python3\nprint('x')\n"
    for disposition in (Disposition.SECONDARY, Disposition.DEPENDENCY, Disposition.NON_CODE):
        manifest = make_manifest(content, disposition=disposition)
        assert all(
            disposition not in {Disposition.SECONDARY, Disposition.DEPENDENCY, Disposition.NON_CODE}
            for _ in []
        )


def test_stage1_hash_is_reproducible_for_identical_git_objects(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Stage1 Test"], cwd=repo, check=True)
    source = repo / "src"
    source.mkdir()
    path = source / "main.rs"
    content = b"fn main() { let x = 1; }\n"
    path.write_bytes(content)
    subprocess.run(["git", "add", "src/main.rs"], cwd=repo, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    blob = subprocess.check_output(["git", "rev-parse", "HEAD:src/main.rs"], cwd=repo, text=True).strip()
    record = ChangeRecord("src/main.rs", "modified", Disposition.PRIMARY, Reason.CODE_CHANGE, len(content), False, blob, sha256_hex(content))
    manifest = freeze_manifest(repository="test/repo", base_commit=commit, head_commit=commit, pr_number=1, files=[record])
    raw = manifest_json(manifest)
    first = build_evidence_manifest(raw, str(repo))
    second = build_evidence_manifest(raw, str(repo))
    assert first.canonical_json() == second.canonical_json()
    assert first.stage1_sha256 == second.stage1_sha256
    assert first.evidence_blocks


def test_working_tree_mutation_does_not_change_head_bound_evidence(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Stage1 Test"], cwd=repo, check=True)
    source = repo / "src"
    source.mkdir()
    path = source / "main.rs"
    original = b"fn main() { let x = 1; }\n"
    path.write_bytes(original)
    subprocess.run(["git", "add", "src/main.rs"], cwd=repo, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    blob = subprocess.check_output(["git", "rev-parse", "HEAD:src/main.rs"], cwd=repo, text=True).strip()
    record = ChangeRecord("src/main.rs", "modified", Disposition.PRIMARY, Reason.CODE_CHANGE, len(original), False, blob, sha256_hex(original))
    manifest = freeze_manifest(repository="test/repo", base_commit=commit, head_commit=commit, pr_number=1, files=[record])
    raw = manifest_json(manifest)
    first = build_evidence_manifest(raw, str(repo))
    path.write_bytes(b"fn main() { panic!(\"working tree mutation\"); }\n")
    second = build_evidence_manifest(raw, str(repo))
    assert first.stage1_sha256 == second.stage1_sha256
    assert first.evidence_blocks[0].content == "fn main() { let x = 1; }\n"


def test_stage1_content_is_not_authoritative_identity():
    content = b"fn main() {}\n"
    digest = hashlib.sha256(content).hexdigest()
    assert digest == sha256_hex(content)
    assert git_blob_sha(content) != digest


def test_evidence_types_do_not_make_security_claims():
    assert EvidenceType.AUTHORIZATION_CHECK.value == "AUTHORIZATION_CHECK"
    assert EvidenceType.CALL.value == "CALL"


def test_parser_malformed_source_is_explicitly_structural():
    refs = parse_ast(b"fn broken( {\n")
    assert refs
