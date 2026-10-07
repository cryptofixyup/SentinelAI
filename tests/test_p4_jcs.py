from p4.acquisition.jcs import canonical_json, sha256_json

def test_jcs_sorts_object_properties():
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'

def test_jcs_number_normalization():
    value = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27]}
    assert canonical_json(value) == b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'

def test_sha256_is_over_jcs_bytes():
    import hashlib
    value = {"hello": "sentinel"}
    assert sha256_json(value) == hashlib.sha256(canonical_json(value)).hexdigest()
