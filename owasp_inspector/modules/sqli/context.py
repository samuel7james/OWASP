from __future__ import annotations

import html
import re
import urllib.parse

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.sqli.payloads import SqliPayloadSet

_CSRF_NAMES = {"csrf", "csrftoken", "csrf_token", "_csrf", "_token", "csrfmiddlewaretoken"}

_WAF_SIGNATURES = {
    "f5 big-ip asm": ["f5", "big-ip", "application security manager"],
    "FortiWeb": ["fortiweb"],
    "Cloudflare": ["cloudflare"],
    "ModSecurity": ["modsecurity"],
}
_WAF_GENERIC_MARKERS = ["request rejected", "the requested url was rejected", "support id is:", "security policy"]

_AUTH_TOKENS = ("user", "username", "email", "login", "pass", "password", "signin", "sign-in", "auth", "account")
_AUTH_PATHS = ("/login", "/signin", "/sign-in", "/auth", "/authenticate", "/session", "/account", "/my-account")


class SqliContext:
    """Async port of Logic/vulnerability_scan/sqli/sqli_context.py — same
    detection helpers (WAF detection, reflection-control verification,
    payload-echo stripping, CSRF token refresh), request I/O now goes through
    the shared AsyncHttpClient instead of a `requests.Session`.
    """

    def __init__(self, http: AsyncHttpClient, payloads: SqliPayloadSet, cookie: str | None = None):
        self.http = http
        self.payloads = payloads
        self.cookie = cookie

    async def send_request(self, method: str, url: str, data_or_params: dict, timeout: float = 10.0):
        headers = {"Cookie": self.cookie} if self.cookie else {}
        if method == "post":
            return await self.http.post(url, data=data_or_params, timeout=timeout, headers=headers)
        if method == "cookie":
            cookie_str = "; ".join(f"{k}={v}" for k, v in data_or_params.items())
            merged = {**headers, "Cookie": cookie_str}
            return await self.http.get(url, headers=merged, timeout=timeout)
        return await self.http.get(url, params=data_or_params, timeout=timeout, headers=headers)

    async def make_request(self, url: str, method: str = "get", timeout: float = 10.0):
        headers = {"Cookie": self.cookie} if self.cookie else {}
        if method.lower() == "post":
            return await self.http.post(url, timeout=timeout, headers=headers)
        return await self.http.get(url, timeout=timeout, headers=headers)

    def detect_waf(self, response) -> str | None:
        if not response:
            return None
        text = response.text.lower()
        combined = text + str(response.headers).lower()
        for name, keywords in _WAF_SIGNATURES.items():
            if any(kw in combined for kw in keywords):
                return name
        if any(marker in combined for marker in _WAF_GENERIC_MARKERS):
            return "Generic WAF"
        return None

    def detect_sql_errors(self, text: str) -> bool:
        return any(re.search(p, text, re.I) for p in self.payloads.error_patterns)

    @staticmethod
    def strip_payload_echoes(text: str, payload: str, reflection: str) -> str:
        for variant in [
            payload,
            html.escape(payload),
            html.escape(payload, quote=False),
            urllib.parse.quote(payload),
            urllib.parse.quote_plus(payload),
            f"'{reflection}'",
            f"&#x27;{reflection}&#x27;",
            f"&#39;{reflection}&#39;",
            f"&apos;{reflection}&apos;",
            f'"{reflection}"',
            f"&quot;{reflection}&quot;",
            f"%27{reflection}%27",
            f"%22{reflection}%22",
        ]:
            text = text.replace(variant, "")
        return text

    @staticmethod
    def inject_url_param(url: str, param: str, payload: str) -> str:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [payload]
        return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query, doseq=True)))

    async def reflection_control_matches(
        self, method: str, turl: str, param: str, defaults: dict, reflection: str, *,
        timeout: float = 10.0, payload: str | None = None,
    ) -> bool:
        control_value = "zyx" if str(reflection).lower() == "abc" else "abc"

        async def _test_control(data_dict: dict) -> bool:
            if method == "get":
                control_url = self.inject_url_param(turl, param, data_dict[param])
                r = await self.make_request(control_url, "get", timeout=timeout)
            else:
                r = await self.send_request(method, turl, data_dict, timeout=timeout)
            if not r:
                return False
            markers = {
                control_value,
                html.escape(control_value),
                html.escape(control_value, quote=False),
                urllib.parse.quote(control_value),
                urllib.parse.quote_plus(control_value),
            }
            return any(m in r.text for m in markers)

        control_data = {**defaults, param: control_value}
        if await _test_control(control_data):
            return True

        if payload and reflection in payload:
            control_payload = payload.replace(reflection, control_value)
            if await _test_control({**defaults, param: control_payload}):
                return True

        return False

    @staticmethod
    def make_vuln_dict(ptype: str, param: str, payload: str, evidence: str, turl: str, method: str, confidence: str = "high") -> dict:
        return {
            "type": f"SQL Injection ({ptype})",
            "parameter": param,
            "payload": payload,
            "evidence": evidence,
            "tool": "builtin_sqli",
            "confidence": confidence,
            "url": turl,
            "method": method,
        }

    @staticmethod
    def is_likely_auth_target(method: str, turl: str, param: str, defaults: dict | None = None) -> bool:
        param_name = str(param or "").lower()
        path = urllib.parse.urlparse(str(turl or "")).path.lower()
        joined_params = " ".join(str(k).lower() for k in (defaults or {}))

        if any(token in param_name for token in _AUTH_TOKENS):
            return True
        if any(token in joined_params for token in _AUTH_TOKENS):
            return True
        if any(path == p or path.startswith(p + "/") for p in _AUTH_PATHS):
            return True
        return method == "post" and ("password" in joined_params or "username" in joined_params)

    async def refresh_csrf(self, url: str, data: dict) -> dict:
        """Fetch a fresh CSRF token from the target page and update the data dict."""
        csrf_keys = [k for k in data if k.lower() in _CSRF_NAMES]
        if not csrf_keys:
            return data

        try:
            resp = await self.make_request(url, "get", timeout=10.0)
            if not resp or not resp.text:
                return data
            for csrf_key in csrf_keys:
                match = re.search(
                    r'<input[^>]*name=["\']' + re.escape(csrf_key) + r'["\'][^>]*value=["\']([^"\']*)["\']',
                    resp.text, re.I,
                )
                if not match:
                    match = re.search(
                        r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']' + re.escape(csrf_key) + r'["\']',
                        resp.text, re.I,
                    )
                if match:
                    data[csrf_key] = match.group(1)
        except Exception:
            pass

        return data
