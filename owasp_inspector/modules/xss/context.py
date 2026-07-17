from __future__ import annotations

import html
import re
import urllib.parse

from bs4 import BeautifulSoup

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.xss.payloads import XssPayloadSet

_EVENT_ATTRS = (
    "onerror",
    "onload",
    "onclick",
    "onmouseover",
    "onfocus",
    "onblur",
    "onsubmit",
    "ontoggle",
    "onstart",
    "oninput",
    "onmouseenter",
    "onchange",
    "onkeyup",
    "onkeydown",
)

_DANGEROUS_MARKERS_FALLBACK = (
    "alert(",
    "confirm(",
    "prompt(",
    "javascript:",
    "onerror=",
    "onload=",
    "<script",
    "</script",
    "${",
)


class XssContext:
    """Async port of the relevant subset of Logic/vulnerability_scan/xss/xss_context.py
    for reflected-XSS scanning: context-aware canary detection, payload-survival
    checks, and injected-request building. Every method here is either pure
    (no I/O — the classification/detection logic) or a thin async request
    wrapper; none of the detection logic itself has changed.
    """

    def __init__(self, http: AsyncHttpClient, payloads: XssPayloadSet, cookie: str | None = None):
        self.http = http
        self.payloads = payloads
        self.cookie = cookie

    async def make_request(self, url: str, method: str = "get", data: dict | None = None, timeout: float = 10.0):
        headers = {"Cookie": self.cookie} if self.cookie else {}
        if method.lower() == "post":
            return await self.http.post(url, data=data, timeout=timeout, headers=headers)
        return await self.http.get(url, timeout=timeout, headers=headers)

    # ── payload/body helpers (pure) ───────────────────────────────────

    @staticmethod
    def body_text_variants(body: str) -> list[str]:
        text = body or ""
        variants = [text]
        decoded = html.unescape(text)
        if decoded not in variants:
            variants.append(decoded)
        return variants

    def body_contains_payload(self, body: str, payload: str) -> bool:
        decoded_payload = html.unescape(payload or "")
        for variant in self.body_text_variants(body):
            if payload and payload in variant:
                return True
            if decoded_payload and decoded_payload in variant:
                return True
        return False

    def payload_dangerous_constructs_survived(self, body: str, payload: str) -> bool:
        """True only if the payload's dangerous markers survived *un-encoded*.
        Markers like "alert(" contain no HTML metacharacters, so they remain
        present as inert text even when the server fully HTML-escapes the
        payload (e.g. "<script>" -> "&lt;script&gt;") — a substring check on
        the marker alone can't tell working JS from neutralized text.
        Checking for stray "<"/">" anywhere in the body doesn't help either
        — every HTML page has those from its own markup. The only reliable
        signal is that the raw payload survived byte-for-byte, undecoded, in
        the response: if the server escaped it, this exact substring won't
        be there even though the inert marker text still is.
        """
        if not body or not payload:
            return False
        payload_lower = payload.lower()
        markers = self.payloads.dangerous_markers or list(_DANGEROUS_MARKERS_FALLBACK)
        payload_markers = [m for m in markers if m in payload_lower]
        if not payload_markers:
            return False
        if payload not in body:
            return False
        body_lower = body.lower()
        return any(marker in body_lower for marker in payload_markers)

    @staticmethod
    def classify_reflection_result(
        ptype: str, hit: dict | None, exact_payload_match: bool, dangerous_survived: bool = False
    ):
        """Combines injection context + exact-match + dangerous-construct-survival
        into a (confidence, status) tuple, or None if not significant. This is
        the legacy classifier's decision table, with one deliberate fix: the
        "reflection-check" payload is a bare canary with no HTML metacharacters,
        so a "low" (bare HTML body text) hit for it means only "this parameter
        echoes input back somewhere" — true for nearly every search box or form
        preview, escaped or not. The legacy classifier reported that as an XSS
        "candidate" unconditionally, which is a false-positive generator on any
        page that reflects input safely. Only report reflection-check when the
        canary landed in real markup structure (medium/high confidence), same
        threshold already used a few lines below for non-exact-match hits.
        """
        if not hit:
            return None

        context = str(hit.get("context", "")).lower()
        hit_confidence = str(hit.get("confidence", "low")).lower()

        if ptype == "reflection-check":
            if hit_confidence == "high":
                return "medium", "candidate"
            if hit_confidence == "medium":
                return "low", "candidate"
            return None

        if not exact_payload_match:
            if hit_confidence == "high":
                return "medium", "candidate"
            if hit_confidence == "medium":
                return "low", "candidate"
            return None

        if "<script>" in context or "handler" in context or "javascript:" in context or "innerhtml" in context:
            return "high", "confirmed"
        if "select/option" in context:
            return "medium", "suspected"
        if hit_confidence == "high":
            return "medium", "suspected"
        if hit_confidence == "medium":
            return "medium", "candidate"
        if dangerous_survived:
            return "low", "candidate"
        return None

    @staticmethod
    def context_detection_marker(payload: str, fallback: str | None = None) -> str:
        if fallback and fallback in (payload or ""):
            return fallback
        for marker in ("alert(", "confirm(", "prompt(", "javascript:", "onerror", "onload", "${"):
            if marker in (payload or ""):
                return marker
        return fallback or payload

    def context_payload_survived(self, body: str, payload: str) -> bool:
        if self.body_contains_payload(body, payload):
            return True
        decoded = html.unescape(body or "")
        for marker in (
            "alert(",
            "confirm(",
            "prompt(",
            "javascript:",
            "onerror=",
            "onload=",
            "<script",
            "</script",
            "${",
        ):
            if marker in payload and marker in decoded:
                return True
        return False

    @staticmethod
    def detect_active_context(body: str, canary: str) -> dict | None:
        """Determines WHERE an injected canary landed (script body, event
        handler, href, HTML attribute, select/option, bare text) and how
        dangerous that context is. Uses a per-scan random canary rather than a
        generic string match, so — unlike the SQLi error-pattern check that
        needed a baseline guard — a false match here would require the exact
        random canary to have pre-existed on the page, which doesn't happen.
        """
        decoded_body = html.unescape(body or "")
        if canary not in (body or "") and canary not in decoded_body:
            return None

        soup = BeautifulSoup(body or "", "html.parser")

        for script in soup.find_all("script"):
            script_text = html.unescape(script.string or script.get_text() or "")
            if canary in script_text:
                idx = script_text.find(canary)
                snippet = script_text[max(0, idx - 30) : idx + len(canary) + 30]
                return {"context": "<script> body", "snippet": snippet, "confidence": "high"}

        for tag in soup.find_all(True):
            for attr in _EVENT_ATTRS:
                val = html.unescape(tag.get(attr, ""))
                if val and canary in val:
                    return {"context": f"{attr} handler", "snippet": f'{attr}="{val[:80]}"', "confidence": "high"}

        for tag in soup.find_all(["a", "area"], href=True):
            href = html.unescape(tag.get("href", ""))
            if canary in href:
                href_lower = href.strip().lower()
                if href_lower.startswith("javascript:") or href_lower.startswith("data:"):
                    return {"context": "javascript: href", "snippet": f'href="{href[:80]}"', "confidence": "high"}
                return {"context": "href attribute", "snippet": f'href="{href[:80]}"', "confidence": "medium"}

        for tag in soup.find_all(True, src=True):
            src = html.unescape(tag.get("src", ""))
            if canary in src:
                src_lower = src.strip().lower()
                if src_lower.startswith("javascript:") or src_lower.startswith("data:"):
                    return {"context": "javascript: src", "snippet": f'src="{src[:80]}"', "confidence": "high"}

        for variant in (body or "", decoded_body):
            js_sink_pattern = re.compile(
                r'(\.innerHTML\s*=\s*["\']?[^";\']*?' + re.escape(canary) + r")", re.IGNORECASE
            )
            m = js_sink_pattern.search(variant)
            if m:
                return {"context": "innerHTML assignment", "snippet": m.group(1)[:100], "confidence": "high"}

        attr_pattern = re.compile(r'<[^>]+=["\'][^">\']*?' + re.escape(canary) + r'[^">\']*?["\']', re.IGNORECASE)
        m = attr_pattern.search(body or "")
        if m:
            return {"context": "HTML attribute", "snippet": m.group(0)[:100], "confidence": "medium"}

        select_pattern = re.compile(r"<(?:select|option)[^>]*>[^<]*?" + re.escape(canary) + r"[^<]*?</", re.IGNORECASE)
        m = select_pattern.search(body or "")
        if m:
            return {
                "context": "select/option element (document.write sink)",
                "snippet": m.group(0)[:100],
                "confidence": "high",
            }

        bare_pattern = re.compile(r">\s*[^<]*?" + re.escape(canary) + r"[^<]*?\s*<")
        m = bare_pattern.search(body or "")
        if m:
            return {"context": "HTML body text", "snippet": m.group(0)[:100], "confidence": "low"}

        return None

    # ── request building ──────────────────────────────────────────────

    @staticmethod
    def normalize_param_values(value):
        if isinstance(value, (list, tuple)):
            return [str(v) for v in value]
        if value is None:
            return [""]
        return [str(value)]

    @classmethod
    def flatten_param_value(cls, value):
        if isinstance(value, list):
            return value[0] if len(value) == 1 else value
        return value

    @classmethod
    def merge_target_query_params(cls, target: dict, param: str, value) -> dict:
        source_url = target.get("url") or ""
        parsed = urllib.parse.urlparse(source_url)
        merged = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, default_value in (target.get("defaults") or {}).items():
            merged[key] = cls.normalize_param_values(default_value)
        merged[param] = cls.normalize_param_values(value)
        return merged

    @classmethod
    def build_injected_get_url(cls, target: dict, param: str, value) -> str | None:
        source_url = target.get("url")
        if not source_url:
            return None
        parsed = urllib.parse.urlparse(source_url)
        base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        query = urllib.parse.urlencode(cls.merge_target_query_params(target, param, value), doseq=True)
        return f"{base_url}?{query}" if query else base_url

    @classmethod
    def build_injected_post_data(cls, target: dict, param: str, value) -> dict:
        data = {}
        for key, default_value in (target.get("defaults") or {}).items():
            data[key] = cls.flatten_param_value(cls.normalize_param_values(default_value))
        data[param] = value
        return data

    async def send_injected_request(self, target: dict, method: str, param: str, value):
        if method == "post":
            turl = target.get("url")
            if not turl:
                return None
            return await self.make_request(turl, "post", data=self.build_injected_post_data(target, param, value))
        test_url = self.build_injected_get_url(target, param, value)
        if not test_url:
            return None
        return await self.make_request(test_url, "get")
