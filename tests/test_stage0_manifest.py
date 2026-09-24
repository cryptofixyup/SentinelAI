from pathlib import Path

import pytest

from src.stage0_manifest import (
    ChangeRecord,
    Disposition,
    Reason,
    classify_path,
    freeze_manifest,
    git_blob_sha,
    safe_join,
    sha256_hex,
    verify_head_binding,
)


def test_component_aware_containment_rejects_prefix_collision(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    sibling = tmp_path / "repo-attacker"
    root.mkdir()
    sibling.mkdir()
    with pytest.raises(ValueError, match="path_traversal_attempt"):
        safe_join(root, "../repo-attacker/secret.py")


def test_component_aware_containment_accepts_descendant(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    candidate = safe_join(root, "src/script.py")
    assert candidate == root / "src/script.py"


def test_misleading_extension_routes_executable_content_to_secondary() -> None:
    disposition, reason = classify_path("src/script.txt", b"#!/usr/bin/env python3\nprint('x')\n")
    assert disposition is Disposition.SECONDARY
    assert reason is Reason.MISLEADING_EXTENSION


def test_normal_code_routes_to_primary() -> None:
    disposition, reason = classify_path("src/main.py", b"def main():\n    return 1\n")
    assert disposition is Disposition.PRIMARY
    assert reason is Reason.CODE_CHANGE


def test_taxonomy_preserves_generated_dependency_and_oversized() -> None:
    content = b"generated"
    assert classify_path("x.py", content, generated=True) == (
        Disposition.GENERATED,
        Reason.GENERATED_ARTIFACT,
    )
    assert classify_path("x.py", content, dependency=True) == (
        Disposition.DEPENDENCY,
        Reason.DEPENDENCY,
    )
    assert classify_path("x.py", content, oversized=True) == (
        Disposition.OVERSIZED,
        Reason.OVERSIZED_ARTIFACT,
    )


def test_head_object_binding_requires_both_object_and_content_identity() -> None:
    content = b"fn main() {}\n"
    verify_head_binding(content, git_blob_sha(content), sha256_hex(content))
    with pytest.raises(ValueError, match="vcs_object_mismatch"):
        verify_head_binding(content, "0" * 40, sha256_hex(content))
    with pytest.raises(ValueError, match="vcs_object_mismatch"):
        verify_head_binding(content, git_blob_sha(content), "0" * 64)


def test_manifest_digest_commits_to_canonical_payload() -> None:
    record = ChangeRecord(
        path="src/main.py",
        change_type="modified",
        disposition=Disposition.PRIMARY,
        reason=Reason.CODE_CHANGE,
        size_bytes=14,
        is_binary=False,
        blob_object=git_blob_sha(b"def main():\n"),
        content_sha256=sha256_hex(b"def main():\n"),
    )
    manifest = freeze_manifest(
        repository="cryptofixyup/SentinelAI",
        base_commit="a" * 40,
        head_commit="b" * 40,
        pr_number=7,
        files=[record],
    )
    assert manifest.manifest_sha256 == sha256_hex(manifest.canonical_json())
    assert manifest.manifest_sha256 == sha256_hex(
        manifest.canonical_json()
    )


def test_manifest_order_is_deterministic() -> None:
    def record(path: str) -> ChangeRecord:
        return ChangeRecord(path, "modified", Disposition.PRIMARY, Reason.CODE_CHANGE, 1, False, None, "0" * 64)

    first = freeze_manifest(
        repository="r", base_commit="a", head_commit="b", pr_number=1,
        files=[record("z.py"), record("a.py")],
    )
    second = freeze_manifest(
        repository="r", base_commit="a", head_commit="b", pr_number=1,
        files=[record("a.py"), record("z.py")],
    )
    assert first.canonical_json() == second.canonical_json()
    assert first.manifest_sha256 == second.manifest_sha256


def test_rename_preserves_removal_addition_and_relationship() -> None:
    records = [
        ChangeRecord("A.py", "renamed_from", Disposition.DELETED, Reason.DELETED, 0, False, "a" * 40, None),
        ChangeRecord("B.py", "renamed_to", Disposition.PRIMARY, Reason.CODE_CHANGE, 10, False, "b" * 40, "c" * 64),
    ]
    manifest = freeze_manifest(
        repository="r", base_commit="a", head_commit="b", pr_number=1, files=records
    )
    types = {item.change_type for item in manifest.files}
    assert {"renamed_from", "renamed_to"} <= types
