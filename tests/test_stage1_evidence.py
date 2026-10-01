from pathlib import Path
import subprocess

import pytest

from src.stage0_manifest import ChangeRecord, Disposition, Reason, freeze_manifest, git_blob_sha, sha256_hex
from src.stage1_evidence import (
    EvidenceType,
    Stage1Error,
    build_evidence_manifest,
    deterministic_evidence_id,
    evidence_id,
    parse_ast,
    verify_stage0_manifest,
)


def git_repo(tmp_path: Path, content: bytes):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Stage1 Test"], cwd=repo, check=True)
    (repo / "src").mkdir()
    (repo / "src/main.rs").write_bytes(content)
    subprocess.run(["git", "add", "src/main.rs"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    blob = subprocess.check_output(["git", "rev-parse", "HEAD:src/main.rs"], cwd=repo, text=True).strip()
    return repo, commit, blob


def make_manifest(commit: str, blob: str, content: bytes, *, disposition=Disposition.PRIMARY, change_type="modified", rename_group_id=None):
    record = ChangeRecord("src/main.rs", change_type, disposition, Reason.CODE_CHANGE, len(content), False, blob, sha256_hex(content), rename_group_id)
    return freeze_manifest(repository="test/repo", base_commit=commit, head_commit=commit, pr_number=1, files=[record])


def manifest_json(manifest):
    payload = manifest.payload()
    payload["manifest_sha256"] = manifest.manifest_sha256
    return payload


def test_stage0_manifest_verification_rejects_tampering(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    raw = manifest_json(make_manifest(commit, blob, content))
    raw["head_commit"] = "c" * 40
    with pytest.raises(Stage1Error, match="stage0_integrity_mismatch"):
        verify_stage0_manifest(raw)


def test_stage0_manifest_verification_accepts_rename_field(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    raw = manifest_json(make_manifest(commit, blob, content, rename_group_id="r1"))
    assert verify_stage0_manifest(raw).files[0].rename_group_id == "r1"


def test_stage0_manifest_unknown_disposition_fails_closed(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    raw = manifest_json(make_manifest(commit, blob, content))
    raw["files"][0]["disposition"] = "VULNERABLE"
    with pytest.raises(Stage1Error, match="stage0_integrity_mismatch"):
        verify_stage0_manifest(raw)


def test_git_object_binding_is_verified_against_commit_path(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    evidence = build_evidence_manifest(manifest_json(make_manifest(commit, blob, content)), str(repo))
    assert evidence.evidence_blocks
    assert evidence.evidence_blocks[0].object_id == blob


def test_working_tree_mutation_does_not_change_head_bound_evidence(tmp_path: Path):
    original = b"fn main() { let x = 1; }\n"
    repo, commit, blob = git_repo(tmp_path, original)
    manifest = make_manifest(commit, blob, original)
    first = build_evidence_manifest(manifest_json(manifest), str(repo))
    (repo / "src/main.rs").write_bytes(b"fn main() { panic!(\"working tree mutation\"); }\n")
    second = build_evidence_manifest(manifest_json(manifest), str(repo))
    assert first.canonical_json() == second.canonical_json()
    assert first.stage1_sha256 == second.stage1_sha256
    assert first.evidence_blocks[0].content == original.decode()


def test_head_object_change_changes_artifact(tmp_path: Path):
    original = b"fn main() { let x = 1; }\n"
    repo, base_commit, base_blob = git_repo(tmp_path, original)
    (repo / "src/main.rs").write_bytes(b"fn main() { let x = 2; }\n")
    subprocess.run(["git", "add", "src/main.rs"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "head"], cwd=repo, check=True)
    head_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    head_blob = subprocess.check_output(["git", "rev-parse", "HEAD:src/main.rs"], cwd=repo, text=True).strip()
    record = ChangeRecord("src/main.rs", "modified", Disposition.PRIMARY, Reason.CODE_CHANGE, 25, False, head_blob, sha256_hex(b"fn main() { let x = 2; }\n"))
    manifest = freeze_manifest(repository="test/repo", base_commit=base_commit, head_commit=head_commit, pr_number=1, files=[record])
    evidence = build_evidence_manifest(manifest_json(manifest), str(repo))
    assert evidence.evidence_blocks
    assert evidence.evidence_blocks[0].source_sha256 == sha256_hex(b"fn main() { let x = 2; }\n")


def test_source_and_node_hashes_are_distinct_bindings(tmp_path: Path):
    content = b"fn main() { let x = 1; }\n"
    repo, commit, blob = git_repo(tmp_path, content)
    evidence = build_evidence_manifest(manifest_json(make_manifest(commit, blob, content)), str(repo))
    block = evidence.evidence_blocks[0]
    exact = content[block.start_byte:block.end_byte]
    assert block.source_sha256 == sha256_hex(content)
    assert block.content_sha256 == sha256_hex(exact)


def test_evidence_id_binds_source_and_node_identity():
    node = type("N", (), {"node_type": "function_item", "start_byte": 1, "end_byte": 2})()
    first = evidence_id(source_sha256="a" * 64, file="src/a.rs", commit="b" * 40, object_id="c" * 40, node=node, evidence_type=EvidenceType.MODIFIED_FUNCTION)
    second = evidence_id(source_sha256="d" * 64, file="src/a.rs", commit="b" * 40, object_id="c" * 40, node=node, evidence_type=EvidenceType.MODIFIED_FUNCTION)
    assert first != second


def test_deterministic_legacy_helper_remains_non_authoritative():
    assert deterministic_evidence_id(0) == "E-000001"
    assert deterministic_evidence_id(1) == "E-000002"


def test_rust_ast_ranges_are_valid():
    content = b"fn main() { let x = 1; if x > 0 { return; } }\n"
    refs = parse_ast(content)
    assert refs
    assert all(0 <= ref.start_byte <= ref.end_byte <= len(content) for ref in refs)


def test_parse_error_fails_closed():
    with pytest.raises(Stage1Error, match="parse_error"):
        parse_ast(b"fn broken( {\n")


def test_non_primary_dispositions_are_not_emitted(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    for disposition, reason in [
        (Disposition.SECONDARY, Reason.MISLEADING_EXTENSION),
        (Disposition.DEPENDENCY, Reason.DEPENDENCY),
        (Disposition.NON_CODE, Reason.NON_CODE),
    ]:
        record = ChangeRecord("src/main.rs", "modified", disposition, reason, len(content), False, blob, sha256_hex(content))
        manifest = freeze_manifest(repository="test/repo", base_commit=commit, head_commit=commit, pr_number=1, files=[record])
        evidence = build_evidence_manifest(manifest_json(manifest), str(repo))
        assert evidence.evidence_blocks == ()


def test_stage1_hash_is_reproducible_for_identical_git_objects(tmp_path: Path):
    content = b"fn main() { let x = 1; }\n"
    repo, commit, blob = git_repo(tmp_path, content)
    manifest = make_manifest(commit, blob, content)
    first = build_evidence_manifest(manifest_json(manifest), str(repo))
    second = build_evidence_manifest(manifest_json(manifest), str(repo))
    assert first.canonical_json() == second.canonical_json()
    assert first.stage1_sha256 == second.stage1_sha256


def test_stage1_hash_is_bound_to_stage0_hash(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    manifest = make_manifest(commit, blob, content)
    evidence = build_evidence_manifest(manifest_json(manifest), str(repo))
    assert evidence.stage0_sha256 == manifest.manifest_sha256
    assert evidence.stage1_sha256 == sha256_hex(evidence.canonical_json())


def test_limits_are_explicitly_incomplete(tmp_path: Path):
    content = b"fn main() { let a = 1; let b = 2; }\n"
    repo, commit, blob = git_repo(tmp_path, content)
    manifest = make_manifest(commit, blob, content)
    evidence = build_evidence_manifest(manifest_json(manifest), str(repo), max_blocks=1)
    assert evidence.incomplete is True
    assert len(evidence.evidence_blocks) == 1


def test_invalid_limits_fail_closed(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    with pytest.raises(Stage1Error, match="invalid_evidence_limits"):
        build_evidence_manifest(manifest_json(make_manifest(commit, blob, content)), str(repo), max_blocks=0)


def test_security_semantics_are_not_emitted_as_facts():
    assert "AUTHORIZATION_CHECK" not in {item.value for item in EvidenceType}
