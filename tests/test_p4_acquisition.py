import hashlib
import json
from pathlib import Path
import pytest

from p4.acquisition.capture import canonical_json, sha256_json, validate_case

def test_canonical_json_is_stable():
    assert canonical_json({'b':2,'a':1}) == canonical_json({'a':1,'b':2})

def test_sha256_matches_stdlib():
    value={'hello':'sentinel'}
    assert sha256_json(value) == hashlib.sha256(canonical_json(value)).hexdigest()

def test_unfrozen_case_is_rejected():
    case=json.loads(Path('p4/case/CASE.json').read_text())
    with pytest.raises(SystemExit, match='FROZEN'):
        validate_case(case)
