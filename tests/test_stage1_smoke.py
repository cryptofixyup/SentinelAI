from src.stage1_evidence import deterministic_evidence_id


def test_stage1_import_and_id_smoke():
    assert deterministic_evidence_id(0) == "E-000001"
