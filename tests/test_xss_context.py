from owasp_inspector.modules.xss.context import XssContext
from owasp_inspector.modules.xss.payloads import XssPayloadSet


def _ctx():
    return XssContext(http=None, payloads=XssPayloadSet(dangerous_markers=["<script", "onerror="]))


def test_detect_active_context_finds_script_body():
    canary = "xSsT3sTabcdef"
    hit = XssContext.detect_active_context(f"<html><script>var x = '{canary}';</script></html>", canary)
    assert hit["context"] == "<script> body"
    assert hit["confidence"] == "high"


def test_detect_active_context_finds_event_handler():
    canary = "xSsT3sTabcdef"
    hit = XssContext.detect_active_context(f'<img src=x onerror="{canary}">', canary)
    assert hit["context"] == "onerror handler"
    assert hit["confidence"] == "high"


def test_detect_active_context_returns_none_when_canary_absent():
    assert XssContext.detect_active_context("<html>nothing here</html>", "xSsT3sTabcdef") is None


def test_detect_active_context_html_escaped_canary_is_not_a_script_body_hit():
    # The canary is HTML-escaped (properly encoded output) — BeautifulSoup
    # will not parse it as being inside a real <script> tag's executable text,
    # it should surface as plain body text at worst, not a high-confidence hit.
    canary = "xSsT3sTabcdef"
    escaped = f"&lt;script&gt;{canary}&lt;/script&gt;"
    hit = XssContext.detect_active_context(f"<html><body>{escaped}</body></html>", canary)
    assert hit is not None
    assert hit["context"] != "<script> body"


def test_classify_reflection_result_reflection_check_ignores_bare_body_text_hit():
    # Regression: "reflection-check" is a bare canary with no HTML
    # metacharacters — a "low"/HTML-body-text hit just means the input is
    # echoed back somewhere, which is true of most search/form fields
    # whether or not they're safely escaped. Reporting that unconditionally
    # as an XSS candidate is a false-positive generator; only real markup
    # structure (medium/high confidence) should count.
    hit = {"context": "HTML body text", "confidence": "low"}
    assert XssContext.classify_reflection_result("reflection-check", hit, exact_payload_match=True) is None


def test_classify_reflection_result_reflection_check_reports_structural_hit():
    hit = {"context": "<script> body", "confidence": "high"}
    assert XssContext.classify_reflection_result("reflection-check", hit, exact_payload_match=True) == ("medium", "candidate")


def test_classify_reflection_result_confirms_script_context_with_exact_match():
    hit = {"context": "<script> body", "confidence": "high"}
    result = XssContext.classify_reflection_result("script-tag", hit, exact_payload_match=True, dangerous_survived=True)
    assert result == ("high", "confirmed")


def test_classify_reflection_result_none_when_no_hit():
    assert XssContext.classify_reflection_result("script-tag", None, exact_payload_match=True) is None


def test_classify_reflection_result_low_confidence_body_text_needs_dangerous_survival():
    hit = {"context": "HTML body text", "confidence": "low"}
    assert XssContext.classify_reflection_result("script-tag", hit, exact_payload_match=True, dangerous_survived=False) is None
    assert XssContext.classify_reflection_result("script-tag", hit, exact_payload_match=True, dangerous_survived=True) == ("low", "candidate")


def test_payload_dangerous_constructs_survived_true_when_marker_present():
    ctx = _ctx()
    assert ctx.payload_dangerous_constructs_survived("<script>alert(1)</script>", "<script>alert(1)</script>") is True


def test_payload_dangerous_constructs_survived_false_when_escaped():
    ctx = _ctx()
    assert ctx.payload_dangerous_constructs_survived("&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>") is False


def test_payload_dangerous_constructs_survived_false_when_marker_has_no_metachars_but_payload_escaped():
    # Regression: dangerous_markers like "alert(" contain no HTML
    # metacharacters, so they remain in the body as inert text even after
    # the server fully HTML-escapes the payload. A naive substring check on
    # just the marker (or on "is there a stray < anywhere on the page")
    # would wrongly call this "survived". Only a literal, undecoded match of
    # the full payload counts.
    ctx = XssContext(http=None, payloads=XssPayloadSet(dangerous_markers=["alert("]))
    body = "<html><body>hi &lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt; bye</body></html>"
    payload = '<script>alert("x")</script>'
    assert ctx.payload_dangerous_constructs_survived(body, payload) is False


def test_body_contains_payload_matches_html_entity_decoded_variant():
    ctx = _ctx()
    assert ctx.body_contains_payload("prefix &#x27;marker&#x27; suffix", "'marker'") is True


def test_merge_target_query_params_includes_defaults_and_injected_value():
    target = {"url": "https://x/search", "defaults": {"q": "hello", "page": "1"}}
    merged = XssContext.merge_target_query_params(target, "q", "INJECTED")
    assert merged["q"] == ["INJECTED"]
    assert merged["page"] == ["1"]


def test_build_injected_get_url_produces_clean_query_string():
    target = {"url": "https://x/search", "defaults": {"q": "hello"}}
    url = XssContext.build_injected_get_url(target, "q", "<script>")
    assert url.startswith("https://x/search?")
    assert "q=" in url


def test_build_injected_post_data_merges_defaults():
    target = {"defaults": {"name": "guest", "comment": ""}}
    data = XssContext.build_injected_post_data(target, "comment", "<script>")
    assert data["name"] == "guest"
    assert data["comment"] == "<script>"
