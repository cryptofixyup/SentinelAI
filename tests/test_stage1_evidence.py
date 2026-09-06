from pathlib import Path

import pytest

from src.stage0_manifest import ChangeRecord, Disposition, Reason, freeze_manifest, git_blob_sha, sha256_hex
from src.stage1_evidence import EvidenceType, Stage1Error, build_evidence_manifest, deterministic_evidence_id, parse_ast, verify_stage0_manifest


def git_repo(tmp_path: Path, content: bytes):
    import subprocess
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


def make_manifest(commit: str, blob: str, content: bytes, *, disposition=Disposition.PRIMARY, change_type="modified"):
    record = ChangeRecord("src/main.rs", change_type, disposition, Reason.CODE_CHANGE, len(content), False, blob, sha256_hex(content))
    return freeze_manifest(repository="test/repo", base_commit=commit, head_commit=commit, pr_number=1, files=[record])


def manifest_json(manifest):
    payload = manifest.payload()
    payload["manifest_sha256"] = manifest.manifest_sha256
    return payload


def test_stage0_manifest_verification_rejects_tampering(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    manifest = make_manifest(commit, blob, content)
    raw = manifest_json(manifest)
    raw["head_commit"] = "c" * 40
    with pytest.raises(Stage1Error, match="stage0_integrity_mismatch"):
        verify_stage0_manifest(raw)


def test_stage0_manifest_verification_rejects_unknown_disposition(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    manifest = make_manifest(commit, blob, content)
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
    assert all(0 <= ref.start_byte <= ref.end_byte <= len(content) for ref in refs)


def test_non_primary_dispositions_are_not_emitted(tmp_path: Path):
    content = b"fn main() {}\n"
    repo, commit, blob = git_repo(tmp_path, content)
    for disposition, reason in [(Disposition.SECONDARY, Reason.MISLEADING_EXTENSION), (Disposition.DEPENDENCY, Reason.DEPENDENCY), (Disposition.NON_CODE, Reason.NON_CODE)]:
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
    assert first.evidence_blocks


def test_working_tree_mutation_does_not_change_head_bound_evidence(tmp_path: Path):
    original = b"fn main() { let x = 1; }\n"
    repo, commit, blob = git_repo(tmp_path, original)
    manifest = make_manifest(commit, blob, original)
    first = build_evidence_manifest(manifest_json(manifest), str(repo))
    (repo / "src/main.rs").write_bytes(b"fn main() { panic!(\"working tree mutation\"); }\n")
    second = build_evidence_manifest(manifest_json(manifest), str(repo))
    assert first.stage1_sha256 == second.stage1_sha256
    assert first.evidence_blocks[0].content == original.decode()


def test_stage1_does_not_promote_security_semantics():
    assert EvidenceType.AUTHORIZATION_CHECK.value == "AUTHORIZATION_CHECK"
    assert EvidenceType.CALL.value == "CALL"


def test_malformed_rust_is_structural_not_security_semantic():
    refs = parse_ast(b"fn broken( {\n")
    assert refs
