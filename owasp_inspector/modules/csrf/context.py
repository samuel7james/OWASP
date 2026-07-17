from __future__ import annotations

from bs4 import BeautifulSoup

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.csrf.patterns import CSRF_ERROR_RE, NON_STATE_CHANGING_PATHS, SUCCESS_RE

DEFAULT_TOKEN_NAMES = {
    "csrf", "csrf_token", "csrftoken", "_csrf", "xsrf", "_xsrf",
    "xsrf_token", "xsrf-token", "_token", "authenticity_token",
    "__requestverificationtoken", "csrfmiddlewaretoken", "_csrf_token",
    "token", "anti_forgery_token", "form_token", "form_key", "nonce",
    "_wpnonce", "wp_nonce", "ic-csrf-token", "csrf-token",
}


class CsrfContext:
    """Async port of the relevant subset of
    Logic/vulnerability_scan/csrf/bypass_strategies.py's `CSRFBypassTest`
    base class: request helpers, test-data population, fresh-token
    fetching, and the action-success classifier. Ported faithfully with one
    deliberate fix (see `is_action_successful`) — the request I/O is what's
    new here, not the detection logic itself.
    """

    def __init__(self, http: AsyncHttpClient, token_names: set[str] | None = None, cookie: str | None = None):
        self.http = http
        self.token_names = token_names or set(DEFAULT_TOKEN_NAMES)
        self.cookie = cookie

    async def get(self, url: str, *, params: dict | None = None, headers: dict | None = None, timeout: float = 15.0):
        hdrs = {"Cookie": self.cookie} if self.cookie else {}
        if headers:
            hdrs.update(headers)
        return await self.http.get(url, params=params, headers=hdrs, timeout=timeout)

    async def post(self, url: str, *, data=None, headers: dict | None = None, timeout: float = 15.0):
        hdrs = {"Cookie": self.cookie} if self.cookie else {}
        if headers:
            hdrs.update(headers)
        # A raw str/bytes body (used for the text/plain and JSON-disguised
        # content-type bypass tests) goes through httpx's `content=`, not
        # `data=` — passing a bare string to `data=` is deprecated and,
        # more importantly, wouldn't be sent as-is.
        if isinstance(data, (str, bytes)):
            return await self.http.post(url, content=data, headers=hdrs, timeout=timeout)
        return await self.http.post(url, data=data, headers=hdrs, timeout=timeout)

    async def submit(self, url: str, method: str, data: dict, *, headers: dict | None = None):
        """Submit `data` using the form's own method. Some vulnerable apps
        (DVWA's own CSRF lab included) use GET for a state-changing action —
        testing token presence/removal/tampering only means something if the
        attack request is sent the same way the real form is."""
        if (method or "post").lower() == "get":
            return await self.get(url, params=data, headers=headers)
        return await self.post(url, data=data, headers=headers)

    async def get_baseline(self, page_url: str):
        """Fetch the page before the attack to establish a baseline for comparison."""
        return await self.get(page_url)

    def populate_test_data(self, data: dict) -> dict:
        out = dict(data)
        for key, val in out.items():
            k_lower = key.lower()
            if k_lower == "email":
                out[key] = "csrf-test@evil.com"
            elif not val and k_lower not in self.token_names:
                out[key] = "test_value"
        return out

    async def get_fresh_token(self, page_url: str) -> tuple[str | None, str | None]:
        r = await self.get(page_url)
        if not r:
            return None, None
        soup = BeautifulSoup(r.text, "html.parser")
        for inp in soup.find_all("input"):
            name = inp.get("name", "")
            if name.lower() in self.token_names:
                return name, inp.get("value", "")
        return None, None

    @staticmethod
    def is_action_successful(response, form: dict | None = None, baseline=None) -> bool:
        """Determine if a CSRF bypass attempt succeeded. Ported from
        `CSRFBypassTest._is_action_successful` with one fix: the legacy
        version only gated the *last* branch (bare "200 OK, body differs
        from baseline") on a baseline comparison — the explicit
        SUCCESS_RE match above it fired unconditionally, even when a
        baseline was available and already contained the same "success"
        wording (e.g. static boilerplate, or a page that always renders a
        dormant "alert-success" banner). That's the same missing-baseline
        false-positive class found in the SQLi/XSS ports: a signal that was
        already true before the attack proves nothing about the attack.
        Now, whenever a baseline is available, a SUCCESS_RE hit only counts
        if the baseline didn't already contain it.
        """
        if not response:
            return False

        body = response.text.lower()

        if CSRF_ERROR_RE.search(body):
            return False
        if response.status_code in (403, 401, 400):
            return False

        baseline_body = baseline.text if baseline is not None else None

        if SUCCESS_RE.search(response.text):
            if baseline_body is None or not SUCCESS_RE.search(baseline_body):
                return True

        response_url = str(response.url)
        if "/my-account" in response_url and response.status_code == 200:
            if "csrf-test@evil.com" in response.text:
                return True
            form_url = (form or {}).get("url", "")
            if not any(p in form_url.lower() for p in NON_STATE_CHANGING_PATHS):
                return True

        if response.status_code == 302:
            location = response.headers.get("Location", "")
            if "/my-account" in location or "/profile" in location:
                form_url = (form or {}).get("url", "")
                if not any(p in form_url.lower() for p in NON_STATE_CHANGING_PATHS):
                    return True

        if baseline_body is not None and response.status_code == 200:
            lower_baseline = baseline_body.lower()
            if len(body) > 0 and len(lower_baseline) > 0:
                diff_ratio = abs(len(body) - len(lower_baseline)) / max(len(lower_baseline), 1)
                if diff_ratio > 0.05 and "error" not in body[:500] and "invalid" not in body[:500]:
                    return True
                if "csrf-test@evil.com" in body or "csrf-test" in body:
                    return True
            return False

        return False
