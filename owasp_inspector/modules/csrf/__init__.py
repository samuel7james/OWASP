from __future__ import annotations

import asyncio

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.core.models import Finding
from owasp_inspector.core.module import Module, ScanContext
from owasp_inspector.core.registry import register_module
from owasp_inspector.modules._raw_finding import finding_from_raw
from owasp_inspector.modules.csrf import bypass_tests as bypass_tests_module
from owasp_inspector.modules.csrf.bypass_tests import CORE_BYPASS_TESTS, test_no_token_defense, test_token_entropy
from owasp_inspector.modules.csrf.context import DEFAULT_TOKEN_NAMES, CsrfContext
from owasp_inspector.modules.csrf.patterns import NON_STATE_CHANGING_PATHS


def _build_forms(discovery) -> list[dict]:
    """Builds the same form dict shape the legacy `CSRFScanner.scan()` did
    from its `targets['post']` list, from `discovery.targets` instead —
    finally letting this module read shared discovery like the SQLi/XSS
    ports, rather than crawling independently.

    Includes GET-method forms too (`is_form=True`), not just POST: DVWA's
    own CSRF lab uses `<form method="GET">` for its password-change action,
    and state-changing GET is a real, common CSRF pattern in the wild —
    excluding it entirely would mean this module finds zero targets against
    one of the most canonical CSRF practice pages that exists. A bare
    crawled link with a query string (`is_form=False`) is not tested here;
    there's no form to remove a token from and no reason to believe it's
    state-changing.
    """
    forms = []
    seen = set()
    for t in discovery.targets:
        if t.method == "get" and not t.is_form:
            continue
        key = (t.url, tuple(sorted(t.params)))
        if key in seen:
            continue
        seen.add(key)

        form = {
            "url": t.url,
            "page_url": t.url,
            "method": t.method.upper(),
            "params": t.params,
            "defaults": dict(t.defaults),
        }
        form["has_token"] = any(p.lower() in DEFAULT_TOKEN_NAMES for p in t.params)
        if form["has_token"]:
            for p in t.params:
                if p.lower() in DEFAULT_TOKEN_NAMES:
                    form["token_field"] = p
                    form["token_value"] = t.defaults.get(p, "")
                    break
        forms.append(form)
    return forms


# Method-switching/override tests only make sense when the form's real
# method is POST — they test whether *changing away* from POST bypasses
# validation, which is meaningless for a form that's already GET-native.
_METHOD_AGNOSTIC_TESTS = (
    bypass_tests_module.test_no_token_defense,
    bypass_tests_module.test_remove_token,
    bypass_tests_module.test_empty_token,
    bypass_tests_module.test_tampered_token,
    bypass_tests_module.test_token_entropy,
)


@register_module
class CsrfModule(Module):
    """Native async CSRF bypass-detection module: token
    presence/removal/tampering, method-based bypasses, and token-entropy
    analysis. Categorized under A01 (Broken Access Control) — the OWASP
    2021 Top 10 dropped CSRF as its own category and community guidance
    places it there, since it's fundamentally a failure to enforce
    authorization on a state-changing request.

    Implements 10 of the classic form-level bypass categories (see
    bypass_tests.py's module docstring for what's out of scope and why),
    with every test fetching and checking against a baseline response
    before confirming a bypass — see context.py's `is_action_successful`
    docstring for the false-positive class that guards against.

    Not covered: an authenticated-login flow (and the two bypass tests
    that depend on a second authenticated session), broader
    SameSite/Referer/CORS/CRLF/clickjacking/token-leakage checks — a
    substantially larger, more specialized subsystem in its own right —
    and generating exploit-PoC HTML (an artifact-generation feature, not
    detection logic).
    """

    name = "csrf"
    owasp_category = "A01:2021-Broken Access Control"

    async def run(self, context: ScanContext) -> list[Finding]:
        discovery = context.discovery
        if discovery is None or not discovery.ok:
            return []

        forms = _build_forms(discovery)
        if not forms:
            return []

        settings = context.settings
        max_concurrency = getattr(settings, "scan_sqli_workers", 10) if settings else 10

        async with AsyncHttpClient(max_concurrency=max_concurrency, timeout=15.0, max_retries=0) as http:
            ctx = CsrfContext(http, cookie=context.target.cookie)
            semaphore = asyncio.Semaphore(max_concurrency)

            async def _run_form(form: dict) -> list[dict]:
                is_non_state_changing = any(p in form["url"].lower() for p in NON_STATE_CHANGING_PATHS)
                if is_non_state_changing:
                    tests = (test_no_token_defense, test_token_entropy)
                elif form["method"] == "GET":
                    tests = _METHOD_AGNOSTIC_TESTS
                else:
                    tests = CORE_BYPASS_TESTS

                results = []
                async with semaphore:
                    for test in tests:
                        try:
                            res = await test(ctx, form)
                        except Exception:
                            res = None
                        if res:
                            results.append(res)
                return results

            all_results = await asyncio.gather(*(_run_form(form) for form in forms))

        raw_findings = [f for results in all_results for f in results]
        return [
            finding_from_raw(f, module=self.name, owasp_category=self.owasp_category, target_url=discovery.final_url)
            for f in raw_findings
        ]
