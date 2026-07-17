from owasp_inspector.modules.xss.payloads import load_xss_payloads


def test_loads_real_payload_corpus():
    payload_set = load_xss_payloads()
    assert len(payload_set.xss_payloads) > 0
    assert len(payload_set.dangerous_markers) > 0


def test_required_stored_dom_bypass_payloads_always_present():
    payload_set = load_xss_payloads()
    payloads = {p for p, _ in payload_set.xss_payloads}
    assert any('<img src=1 onerror=alert("{c}")>' in p for p in payloads)


def test_cached_after_first_load():
    first = load_xss_payloads()
    second = load_xss_payloads()
    assert first is second
