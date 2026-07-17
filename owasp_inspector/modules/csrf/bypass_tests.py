from __future__ import annotations

import math
from collections import Counter

from owasp_inspector.modules.csrf.context import CsrfContext
from owasp_inspector.modules.csrf.patterns import NON_STATE_CHANGING_PATHS

"""Async port of the 10 core, single-session bypass tests from
Logic/vulnerability_scan/csrf/bypass_strategies.py. Each function mirrors
its legacy class's `test()` method line-for-line (request shape, ordering,
evidence text) with two changes applied uniformly: the I/O is native async,
and every test now fetches and passes a baseline to `is_action_successful`
(the legacy engine only did this for 2 of the 15 tests — see context.py's
docstring for why that mattered).

Not ported (documented, not silently dropped):
- CrossSessionTokenTest, NonSessionCookieTokenTest: require a second
  authenticated session via the legacy Authenticator, which itself assumes
  a fixed `/login` path unrelated to this engine's discovery-driven design.
  A generic auto-login flow is a real feature to build, not a mechanical
  port.
- TokenReuseTest, CustomHeaderBypassTest: require performing the real
  state-changing action twice in sequence to compare outcomes — a
  meaningfully different risk/write profile than the other tests here,
  worth scoping as its own follow-up rather than folding in silently.
All four remain available via `owasp-inspector-legacy-menu`.
"""


def _shannon_entropy(token: str) -> float:
    if not token:
        return 0.0
    counts = Counter(token)
    length = len(token)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def _levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def _detect_token_encoding(token: str) -> list[tuple[str, str]]:
    """Flags a token as weak only if decoding it reveals a shorter,
    structured, human-readable secret underneath (e.g. base64 of
    "user:42:1699999999") — that's a real sign the token isn't actually
    random. The legacy version also flagged any token merely matching a hex
    or md5/sha1-length charset as "encoded", but hex-encoding random bytes
    is one of the most common, legitimate ways to generate a secure token
    (Django, Rails, and Express's csurf all do this) — format alone says
    nothing about whether the underlying bytes are predictable, so that
    would flag huge numbers of perfectly secure tokens as weak purely for
    looking like hex. Removed; Shannon entropy (checked separately) already
    covers whether the token itself is low-entropy.
    """
    import base64
    import re

    results = []
    if re.match(r"^[A-Za-z0-9+/=]{16,}$", token) and len(token) % 4 == 0:
        try:
            # Strict decoding on purpose: a genuinely random token
            # interpreted as base64 almost never decodes to fully valid
            # UTF-8, so this only fires on a real encoded secret underneath.
            # `errors="ignore"` would silently drop the invalid bytes a
            # random token produces, leaving a short garbage fragment that
            # still passes `isprintable()` by chance — exactly the kind of
            # coincidental match that generates a false "weak token" report.
            decoded = base64.b64decode(token).decode("utf-8")
            if decoded.isprintable() and len(decoded) > 4:
                results.append(("base64", decoded))
        except Exception:
            pass
    return results


def _page_url(form: dict) -> str:
    return form.get("page_url") or form.get("url", "")


async def test_no_token_defense(ctx: CsrfContext, form: dict) -> dict | None:
    if form.get("has_token"):
        return None
    form_url = form.get("url", "")
    if any(p in form_url.lower() for p in NON_STATE_CHANGING_PATHS):
        return None

    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    r = await ctx.submit(form_url, form.get("method", "post"), data)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (No Defenses)",
            "parameter": "none",
            "payload": "direct_form_submission",
            "evidence": f"Form at {form_url} has no CSRF token and accepts cross-origin submissions.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_remove_token(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    await ctx.get_fresh_token(_page_url(form))
    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    data.pop(token_field, None)

    r = await ctx.submit(form_url, form.get("method", "post"), data)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (Token Not Required)",
            "parameter": token_field,
            "payload": "remove_token",
            "evidence": f"Form at {form_url} accepted submission with CSRF token '{token_field}' removed entirely.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_empty_token(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    name, _ = await ctx.get_fresh_token(_page_url(form))
    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    if name:
        data[name] = ""
    else:
        data[token_field] = ""

    r = await ctx.submit(form_url, form.get("method", "post"), data)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (Empty Token Accepted)",
            "parameter": token_field,
            "payload": "empty_token",
            "evidence": f"Form at {form_url} accepted submission with empty CSRF token.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_method_switch(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    if token_field:
        data.pop(token_field, None)

    r = await ctx.get(form_url, params=data)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (Method Switch Bypass)",
            "parameter": token_field or "method",
            "payload": "POST_to_GET",
            "evidence": f"Form at {form_url} accepted GET request bypassing POST CSRF validation.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_method_override(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    if token_field:
        data.pop(token_field, None)
    data["_method"] = "POST"

    r = await ctx.get(form_url, params=data)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (SameSite Lax Bypass via Method Override)",
            "parameter": "_method",
            "payload": "GET with _method=POST",
            "evidence": f"Form at {form_url} accepts GET?_method=POST, bypassing SameSite Lax cookie restrictions.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_method_override_put(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    if token_field:
        data.pop(token_field, None)
    data["_method"] = "PUT"

    r = await ctx.post(form_url, data=data)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (Method Override Bypass)",
            "parameter": "_method",
            "payload": "POST with _method=PUT",
            "evidence": f"Form at {form_url} accepts POST body parameter _method=PUT, bypassing CSRF validation.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_header_override(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    if token_field:
        data.pop(token_field, None)

    headers = {"X-HTTP-Method-Override": "PUT", "X-Method-Override": "PUT"}
    r = await ctx.post(form_url, data=data, headers=headers)
    if ctx.is_action_successful(r, form, baseline=baseline):
        return {
            "type": "CSRF (Header Override Bypass)",
            "parameter": "X-HTTP-Method-Override",
            "payload": "X-HTTP-Method-Override: PUT",
            "evidence": f"Form at {form_url} accepts X-HTTP-Method-Override header, bypassing CSRF validation.",
            "tool": "native_csrf",
            "confidence": "high",
            "form_url": form_url,
        }
    return None


async def test_tampered_token(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")

    token_name, original_token = await ctx.get_fresh_token(_page_url(form))
    if not original_token:
        return None

    baseline = await ctx.get_baseline(_page_url(form))
    tampering_tests = [
        ("truncated", original_token[:8]),
        ("reversed", original_token[::-1]),
        ("null_byte", original_token[:4] + "\x00" + original_token[5:]),
        ("one_char_change", original_token[:-1] + ("a" if original_token[-1] != "a" else "b")),
        ("static_fake", "a" * 40),
    ]

    for tamper_name, tampered_value in tampering_tests:
        data = form.get("defaults", {}).copy()
        data[token_name] = tampered_value

        r = await ctx.submit(form_url, form.get("method", "post"), data)
        if ctx.is_action_successful(r, form, baseline=baseline):
            return {
                "type": f"CSRF (Broken Token Validation - {tamper_name})",
                "parameter": token_name,
                "payload": f"tampered_token_{tamper_name}",
                "evidence": (
                    f"Form at {form_url} accepted a {tamper_name} CSRF token. "
                    f"Original: {original_token[:16]}... Tampered: {tampered_value[:16]}..."
                ),
                "tool": "native_csrf",
                "confidence": "high",
                "form_url": form_url,
            }
    return None


async def test_content_type_switch(ctx: CsrfContext, form: dict) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")
    token_field = form.get("token_field")

    baseline = await ctx.get_baseline(_page_url(form))
    data = ctx.populate_test_data(form.get("defaults", {}))
    if token_field:
        data.pop(token_field, None)

    import json as _json

    body_str = "&".join(f"{k}={v}" for k, v in data.items())
    content_type_tests = [
        ("text/plain", body_str),
        ("application/json", _json.dumps(data)),
    ]

    for ct_name, body in content_type_tests:
        r = await ctx.post(form_url, data=body, headers={"Content-Type": ct_name})
        if ctx.is_action_successful(r, form, baseline=baseline):
            return {
                "type": f"CSRF (Content-Type Bypass: {ct_name})",
                "parameter": "Content-Type",
                "payload": f"Content-Type: {ct_name}",
                "evidence": (
                    f"Form at {form_url} accepted submission with Content-Type: {ct_name} "
                    f"without CSRF token. This bypasses CORS preflight for text/plain."
                ),
                "tool": "native_csrf",
                "confidence": "high",
                "form_url": form_url,
            }
    return None


async def test_token_entropy(ctx: CsrfContext, form: dict, *, num_samples: int = 5, entropy_threshold: float = 2.4, authenticated: bool = False) -> dict | None:
    if not form.get("has_token"):
        return None
    form_url = form.get("url", "")

    tokens = []
    for _ in range(num_samples):
        _, value = await ctx.get_fresh_token(_page_url(form))
        if value:
            tokens.append(value)

    if not tokens:
        return None

    token_name = form.get("token_field", "csrf")
    issues = []

    entropies = [_shannon_entropy(t) for t in tokens]
    avg_entropy = sum(entropies) / len(entropies)
    if avg_entropy < entropy_threshold:
        issues.append(f"Low Shannon entropy: {avg_entropy:.2f} bits/char (threshold: {entropy_threshold})")

    unique = set(tokens)
    if len(unique) < len(tokens) and authenticated:
        reuse_count = len(tokens) - len(unique)
        issues.append(f"Token reuse detected: {reuse_count}/{len(tokens)} duplicates")

    if len(unique) > 1:
        tokens_list = list(unique)
        for i in range(len(tokens_list)):
            broke = False
            for j in range(i + 1, min(i + 3, len(tokens_list))):
                dist = _levenshtein_distance(tokens_list[i], tokens_list[j])
                max_len = max(len(tokens_list[i]), len(tokens_list[j]))
                if dist > 0 and dist < max_len / 2:
                    issues.append(f"Tokens too similar: edit_distance={dist}, length={max_len} (partially static)")
                    broke = True
                    break
            if broke:
                break

    for t in tokens[:2]:
        for enc_type, decoded in _detect_token_encoding(t):
            issues.append(f"Token appears to be {enc_type} encoded: {decoded[:20]}...")

    if issues:
        evidence_str = "; ".join(issues)
        confidence = "medium" if avg_entropy < entropy_threshold else "low"
        return {
            "type": "CSRF (Weak Token - Predictability Risk)",
            "parameter": token_name,
            "payload": f"entropy_analysis (avg={avg_entropy:.2f})",
            "evidence": (
                f"Token analysis for {form_url}: {evidence_str}. "
                f"Samples: {[t[:12] + '...' for t in tokens[:3]]}"
            ),
            "tool": "native_csrf",
            "confidence": confidence,
            "form_url": form_url,
        }
    return None


CORE_BYPASS_TESTS = (
    test_no_token_defense,
    test_remove_token,
    test_empty_token,
    test_method_switch,
    test_method_override,
    test_method_override_put,
    test_header_override,
    test_tampered_token,
    test_content_type_switch,
    test_token_entropy,
)
