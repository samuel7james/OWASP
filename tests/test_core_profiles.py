import pytest

from owasp_inspector.core.profiles import PROFILES, get_profile


def test_default_profile_is_thorough():
    profile = get_profile(None)
    assert profile.name == "thorough"


def test_stealth_profile_is_slower_and_less_concurrent_than_fast():
    fast = PROFILES["fast"]
    stealth = PROFILES["stealth"]
    assert stealth.max_concurrency < fast.max_concurrency
    assert stealth.min_request_interval_seconds > fast.min_request_interval_seconds


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        get_profile("nonexistent")
