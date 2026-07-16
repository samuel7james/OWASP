from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    max_concurrency: int
    timeout: float
    max_retries: int
    min_request_interval_seconds: float


PROFILES: dict[str, ScanProfile] = {
    "fast": ScanProfile(
        name="fast", max_concurrency=20, timeout=10.0, max_retries=1, min_request_interval_seconds=0.0
    ),
    "thorough": ScanProfile(
        name="thorough", max_concurrency=10, timeout=30.0, max_retries=2, min_request_interval_seconds=0.1
    ),
    "stealth": ScanProfile(
        name="stealth", max_concurrency=2, timeout=30.0, max_retries=3, min_request_interval_seconds=1.5
    ),
}

DEFAULT_PROFILE = "thorough"


def get_profile(name: str | None) -> ScanProfile:
    resolved = name or DEFAULT_PROFILE
    try:
        return PROFILES[resolved]
    except KeyError:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown scan profile {resolved!r}. Valid profiles: {valid}") from None
