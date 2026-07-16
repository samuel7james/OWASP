import time

from owasp_inspector.core.ratelimit import RateLimiter


async def test_no_delay_when_interval_is_zero():
    limiter = RateLimiter(min_interval_seconds=0.0)
    start = time.monotonic()
    await limiter.wait_for_turn("https://example.com")
    await limiter.wait_for_turn("https://example.com")
    assert time.monotonic() - start < 0.2


async def test_enforces_minimum_interval_per_host():
    limiter = RateLimiter(min_interval_seconds=0.2)
    start = time.monotonic()
    await limiter.wait_for_turn("https://example.com/a")
    await limiter.wait_for_turn("https://example.com/b")
    assert time.monotonic() - start >= 0.19


async def test_different_hosts_do_not_block_each_other():
    limiter = RateLimiter(min_interval_seconds=5.0)
    start = time.monotonic()
    await limiter.wait_for_turn("https://a.example.com")
    await limiter.wait_for_turn("https://b.example.com")
    assert time.monotonic() - start < 0.5
