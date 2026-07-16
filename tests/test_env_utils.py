from env_utils import env_bool, env_float


def test_env_float_uses_default_when_unset(monkeypatch):
    monkeypatch.delenv("SCAN_TEST_FLOAT", raising=False)
    assert env_float("SCAN_TEST_FLOAT", 2.5) == 2.5


def test_env_float_parses_set_value(monkeypatch):
    monkeypatch.setenv("SCAN_TEST_FLOAT", "7.5")
    assert env_float("SCAN_TEST_FLOAT", 2.5) == 7.5


def test_env_float_falls_back_on_bad_value(monkeypatch):
    monkeypatch.setenv("SCAN_TEST_FLOAT", "not-a-number")
    assert env_float("SCAN_TEST_FLOAT", 2.5) == 2.5


def test_env_bool_true_values(monkeypatch):
    for value in ("1", "true", "YES", "on", "enabled"):
        monkeypatch.setenv("SCAN_TEST_BOOL", value)
        assert env_bool("SCAN_TEST_BOOL") is True


def test_env_bool_default_when_unset(monkeypatch):
    monkeypatch.delenv("SCAN_TEST_BOOL", raising=False)
    assert env_bool("SCAN_TEST_BOOL", True) is True
    assert env_bool("SCAN_TEST_BOOL", False) is False
