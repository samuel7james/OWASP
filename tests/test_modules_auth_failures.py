from owasp_inspector.core.models import ScanTarget
from owasp_inspector.core.module import ScanContext
from owasp_inspector.discovery.models import CookieFlags, DiscoveryResult, ParamTarget
from owasp_inspector.modules.auth_failures import AuthFailuresModule


def _context(**kwargs):
    defaults = dict(target_url="https://example.com/", final_url="https://example.com/", ok=True)
    defaults.update(kwargs)
    discovery = DiscoveryResult(**defaults)
    return ScanContext(target=ScanTarget(url=discovery.final_url), http=None, settings=None, discovery=discovery)


async def test_flags_session_cookie_missing_httponly():
    findings = await AuthFailuresModule().run(
        _context(cookie_flags=[CookieFlags(name="JSESSIONID", secure=True, httponly=False, samesite="Lax")])
    )
    assert any("HttpOnly" in f.title for f in findings)


async def test_flags_session_cookie_missing_samesite():
    findings = await AuthFailuresModule().run(
        _context(cookie_flags=[CookieFlags(name="connect.sid", secure=True, httponly=True, samesite=None)])
    )
    assert any("SameSite" in f.title for f in findings)


async def test_does_not_flag_well_configured_session_cookie():
    findings = await AuthFailuresModule().run(
        _context(cookie_flags=[CookieFlags(name="sessionid", secure=True, httponly=True, samesite="Strict")])
    )
    assert findings == []


async def test_ignores_non_session_cookies():
    findings = await AuthFailuresModule().run(
        _context(cookie_flags=[CookieFlags(name="marketing_pref", secure=False, httponly=False, samesite=None)])
    )
    assert findings == []


async def test_flags_login_form_over_http():
    findings = await AuthFailuresModule().run(
        _context(targets=[ParamTarget(method="post", url="http://example.com/login", params=["username", "password"])])
    )
    assert any("plain HTTP" in f.title for f in findings)


async def test_does_not_flag_non_login_http_form():
    findings = await AuthFailuresModule().run(
        _context(targets=[ParamTarget(method="post", url="http://example.com/search", params=["q"])])
    )
    assert findings == []


async def test_no_findings_when_discovery_failed():
    discovery = DiscoveryResult(target_url="https://x", final_url="https://x", ok=False)
    context = ScanContext(target=ScanTarget(url="https://x"), http=None, settings=None, discovery=discovery)
    assert await AuthFailuresModule().run(context) == []
