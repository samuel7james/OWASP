import httpx

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.csrf import bypass_tests as bt
from owasp_inspector.modules.csrf.context import CsrfContext


def _ctx(handler):
    http = AsyncHttpClient(transport=httpx.MockTransport(handler), max_retries=0)
    return CsrfContext(http, token_names={"csrf_token"})


async def test_no_token_defense_flags_missing_token_when_post_succeeds():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, text="Your profile updated")
        return httpx.Response(200, text="<form></form>")

    ctx = _ctx(handler)
    form = {"url": "https://x/change-email", "params": ["email"], "defaults": {"email": ""}, "has_token": False}
    result = await bt.test_no_token_defense(ctx, form)
    await ctx.http.aclose()

    assert result is not None
    assert result["type"] == "CSRF (No Defenses)"


async def test_no_token_defense_skips_non_state_changing_paths():
    async def handler(request):
        raise AssertionError("should not request a login-path form at all")

    ctx = _ctx(lambda r: httpx.Response(200))
    form = {"url": "https://x/login", "params": ["username"], "defaults": {}, "has_token": False}
    result = await bt.test_no_token_defense(ctx, form)
    assert result is None


async def test_no_token_defense_no_finding_when_form_has_token():
    ctx = _ctx(lambda r: httpx.Response(200, text="profile updated"))
    form = {"url": "https://x/change-email", "params": ["email", "csrf_token"], "defaults": {}, "has_token": True}
    result = await bt.test_no_token_defense(ctx, form)
    await ctx.http.aclose()
    assert result is None


async def test_no_token_defense_no_false_positive_when_page_always_shows_success_text():
    # Regression: the page has static/dormant "success" boilerplate on it
    # regardless of whether the attack worked (e.g. an empty flash-message
    # container using an "alert-success" class, or the phrase appearing in
    # unrelated content). Both baseline and attack response contain it, so
    # it must NOT be reported as a successful bypass.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<div class='hidden'>Settings saved</div><form></form>")

    ctx = _ctx(handler)
    form = {"url": "https://x/change-email", "params": ["email"], "defaults": {"email": ""}, "has_token": False}
    result = await bt.test_no_token_defense(ctx, form)
    await ctx.http.aclose()
    assert result is None


async def test_remove_token_flags_server_accepting_request_without_token():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, text="Account updated")
        return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="tok1">')

    ctx = _ctx(handler)
    form = {"url": "https://x/settings", "params": ["email", "csrf_token"], "defaults": {"email": "", "csrf_token": "tok1"}, "has_token": True, "token_field": "csrf_token"}
    result = await bt.test_remove_token(ctx, form)
    await ctx.http.aclose()

    assert result is not None
    assert result["type"] == "CSRF (Token Not Required)"


async def test_remove_token_no_finding_when_server_rejects():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(403, text="invalid csrf token")
        return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="tok1">')

    ctx = _ctx(handler)
    form = {"url": "https://x/settings", "params": ["email", "csrf_token"], "defaults": {"email": "", "csrf_token": "tok1"}, "has_token": True, "token_field": "csrf_token"}
    result = await bt.test_remove_token(ctx, form)
    await ctx.http.aclose()
    assert result is None


async def test_tampered_token_flags_static_fake_acceptance():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(200, text="Account updated")
        return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="realtoken123456789012345678">')

    ctx = _ctx(handler)
    form = {"url": "https://x/settings", "params": ["email", "csrf_token"], "defaults": {"email": ""}, "has_token": True}
    result = await bt.test_tampered_token(ctx, form)
    await ctx.http.aclose()

    assert result is not None
    assert "Broken Token Validation" in result["type"]


async def test_token_entropy_flags_low_entropy_static_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text='<input type="hidden" name="csrf_token" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">')

    ctx = _ctx(handler)
    form = {"url": "https://x/settings", "params": ["csrf_token"], "defaults": {}, "has_token": True, "token_field": "csrf_token"}
    result = await bt.test_token_entropy(ctx, form, num_samples=3)
    await ctx.http.aclose()

    assert result is not None
    assert "Weak Token" in result["type"]


async def test_token_entropy_no_false_positive_on_secure_random_hex_token():
    # Regression: a real random hex/sha1-shaped token (the normal, secure
    # way many frameworks generate CSRF tokens) must not be flagged as
    # "weak" merely for looking like hex/sha1 by format.
    import secrets

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f'<input type="hidden" name="csrf_token" value="{secrets.token_hex(20)}">')

    ctx = _ctx(handler)
    form = {"url": "https://x/settings", "params": ["csrf_token"], "defaults": {}, "has_token": True, "token_field": "csrf_token"}
    result = await bt.test_token_entropy(ctx, form, num_samples=3, authenticated=True)
    await ctx.http.aclose()
    assert result is None


async def test_token_entropy_no_finding_for_high_entropy_unique_tokens():
    import itertools
    import secrets

    values = itertools.cycle([secrets.token_hex(20) for _ in range(3)])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=f'<input type="hidden" name="csrf_token" value="{next(values)}">')

    ctx = _ctx(handler)
    form = {"url": "https://x/settings", "params": ["csrf_token"], "defaults": {}, "has_token": True, "token_field": "csrf_token"}
    result = await bt.test_token_entropy(ctx, form, num_samples=3, authenticated=True)
    await ctx.http.aclose()
    assert result is None
