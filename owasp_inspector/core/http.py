from __future__ import annotations

import asyncio
import random
import ssl

import httpx

from owasp_inspector.core.ratelimit import RateLimiter

# Duplicates Logic/user_agents.py deliberately: this package must not depend on
# the legacy sys.path-hacked `Logic/` modules. The two lists merge when the
# legacy scanners migrate into owasp_inspector/modules/ in Phase 5.
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


def _permissive_tls_context() -> ssl.SSLContext:
    """This tool must be able to *reach* targets running old/weak TLS
    configurations — a common real state for exactly the internal/lab/legacy
    systems this project's authorized-testing scope covers. Python's modern
    secure-by-default context refuses to even negotiate TLS 1.0/1.1 (and
    OpenSSL's default SECLEVEL=2 blocks the ciphers that go with them), which
    would make such a target simply unreachable rather than assessable —
    `verify=False` alone does not fix this, it only skips certificate checks.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


class AsyncHttpClient:
    """Bounded-concurrency, retrying, rate-limited async HTTP client.

    This is the one place request policy (concurrency cap, backoff, per-host
    pacing) lives for the new engine, so discovery (Phase 4) and every
    assessment module (Phase 5+) share identical, auditable network behavior.
    """

    def __init__(
        self,
        *,
        max_concurrency: int = 10,
        timeout: float = 30.0,
        max_retries: int = 2,
        backoff_base_seconds: float = 0.5,
        min_request_interval_seconds: float = 0.0,
        verify_tls: bool = False,
        headers: dict | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.max_retries = max_retries
        self.backoff_base_seconds = backoff_base_seconds
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._rate_limiter = RateLimiter(min_request_interval_seconds)
        verify: bool | ssl.SSLContext = ssl.create_default_context() if verify_tls else _permissive_tls_context()
        # Tie the connection pool to max_concurrency instead of httpx's fixed
        # defaults (100 max / 20 keepalive regardless of profile) — a stealth
        # scan (max_concurrency=2) has no use for 20 idle kept-alive sockets,
        # and a fast scan benefits from the pool actually matching how many
        # requests can be in flight at once. Keepalive connections let
        # discovery and modules hitting the same host repeatedly reuse a
        # TCP/TLS handshake instead of paying for a new one every request.
        limits = httpx.Limits(max_connections=max_concurrency * 2, max_keepalive_connections=max_concurrency)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=verify,
            follow_redirects=True,
            headers=headers or {},
            transport=transport,
            limits=limits,
        )

    def _random_headers(self) -> dict:
        return {"User-Agent": random.choice(UA_POOL)}

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response | None:
        headers = {**self._random_headers(), **kwargs.pop("headers", {})}

        async with self._semaphore:
            await self._rate_limiter.wait_for_turn(url)

            attempt = 0
            while True:
                try:
                    response = await self._client.request(method, url, headers=headers, **kwargs)
                except httpx.HTTPError:
                    if attempt >= self.max_retries:
                        return None
                else:
                    if response.status_code not in RETRYABLE_STATUS_CODES or attempt >= self.max_retries:
                        return response

                attempt += 1
                await asyncio.sleep(self.backoff_base_seconds * (2 ** (attempt - 1)))

    async def get(self, url: str, **kwargs) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> AsyncHttpClient:
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.aclose()
