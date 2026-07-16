from __future__ import annotations

import asyncio
import time
from urllib.parse import urlparse


class RateLimiter:
    """Per-host minimum-interval limiter — the request-budget safety rail.

    This exists so a multi-module scan (SQLi + XSS + CSRF + future modules,
    all hitting the same target) can't unintentionally turn into a DoS. It is
    deliberately simple (fixed minimum gap between requests to the same host)
    rather than a full token bucket, since the goal is a safety floor, not
    throughput shaping.
    """

    def __init__(self, min_interval_seconds: float = 0.0):
        self.min_interval_seconds = max(0.0, min_interval_seconds)
        self._last_request_at: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _host_key(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc or url

    def _lock_for(self, host: str) -> asyncio.Lock:
        lock = self._locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[host] = lock
        return lock

    async def wait_for_turn(self, url: str) -> None:
        if self.min_interval_seconds <= 0:
            return
        host = self._host_key(url)
        async with self._lock_for(host):
            now = time.monotonic()
            last = self._last_request_at.get(host)
            if last is not None:
                elapsed = now - last
                remaining = self.min_interval_seconds - elapsed
                if remaining > 0:
                    await asyncio.sleep(remaining)
            self._last_request_at[host] = time.monotonic()
