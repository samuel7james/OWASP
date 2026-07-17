from owasp_inspector.modules.sqli.payloads import load_sqli_payloads


def test_loads_real_payload_corpus():
    payload_set = load_sqli_payloads()
    assert len(payload_set.payloads) > 0
    assert len(payload_set.error_patterns) > 0
    assert "MySQL" in payload_set.blind_fingerprint_probes or payload_set.blind_fingerprint_probes


def test_payload_fields_are_normalized():
    payload_set = load_sqli_payloads()
    error_based = next(p for p in payload_set.payloads if "error-based" in p.type)
    assert error_based.payload
    boolean_based = [p for p in payload_set.payloads if p.group]
    assert boolean_based  # at least one boolean-group payload with expected true/false


def test_cached_after_first_load():
    first = load_sqli_payloads()
    second = load_sqli_payloads()
    assert first is second
