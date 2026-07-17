import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.csrf.context import CsrfContext


def _resp(text, status_code=200, url="https://x/settings"):
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, text=text, request=request)


def test_is_action_successful_false_on_no_response():
    assert CsrfContext.is_action_successful(None) is False


def test_is_action_successful_false_on_csrf_error_pattern():
    r = _resp("403 Forbidden: invalid CSRF token")
    assert CsrfContext.is_action_successful(r) is False


def test_is_action_successful_false_on_error_status_code():
    r = _resp("some body", status_code=401)
    assert CsrfContext.is_action_successful(r) is False


def test_is_action_successful_true_on_explicit_success_pattern_no_baseline():
    r = _resp("Your password changed successfully")
    assert CsrfContext.is_action_successful(r) is True


def test_is_action_successful_false_when_success_pattern_already_in_baseline():
    # Regression: the legacy classifier fired on SUCCESS_RE unconditionally,
    # even when a baseline was available and already contained the same
    # wording (e.g. a dormant "alert-success" banner or static boilerplate
    # text that's always on the page). That's the same missing-baseline
    # false-positive class found in the SQLi/XSS ports.
    baseline = _resp("Settings saved automatically on every page load.")
    r = _resp("Settings saved automatically on every page load.")
    assert CsrfContext.is_action_successful(r, baseline=baseline) is False


def test_is_action_successful_true_when_success_pattern_is_new_relative_to_baseline():
    baseline = _resp("<form>...</form>")
    r = _resp("<p>Settings saved.</p>")
    assert CsrfContext.is_action_successful(r, baseline=baseline) is True


def test_is_action_successful_false_without_baseline_and_no_explicit_signal():
    # Without a baseline, a bare 200 OK is not enough to confirm a bypass.
    r = _resp("<html>some ordinary page</html>")
    assert CsrfContext.is_action_successful(r) is False


def test_is_action_successful_true_on_significant_body_diff_from_baseline():
    baseline = _resp("<html>short</html>")
    r = _resp("<html>" + ("this page is now much longer than before " * 10) + "</html>")
    assert CsrfContext.is_action_successful(r, baseline=baseline) is True


def test_is_action_successful_false_on_trivial_body_diff_from_baseline():
    # A one-character difference (e.g. a rotating CSRF token value) in an
    # otherwise long, stable page should stay under the 5% diff-ratio
    # threshold and not be mistaken for the action having succeeded.
    baseline = _resp("<html>" + ("stable unchanging content " * 20) + "token=aaaa</html>")
    r = _resp("<html>" + ("stable unchanging content " * 20) + "token=bbbb</html>")
    assert CsrfContext.is_action_successful(r, baseline=baseline) is False


def test_populate_test_data_fills_email_and_blank_fields_but_not_tokens():
    ctx = CsrfContext(http=None, token_names={"csrf_token"})
    data = ctx.populate_test_data({"email": "", "csrf_token": "", "name": ""})
    assert data["email"] == "csrf-test@evil.com"
    assert data["csrf_token"] == ""  # token fields are left alone
    assert data["name"] == "test_value"


async def test_get_fresh_token_extracts_matching_hidden_input():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='<form><input type="hidden" name="csrf_token" value="abc123"></form>')

    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    ctx = CsrfContext(http, token_names={"csrf_token"})
    name, value = await ctx.get_fresh_token("https://x/form")
    await http.aclose()
    assert name == "csrf_token"
    assert value == "abc123"
