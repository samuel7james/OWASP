import pytest

from owasp_inspector.core.exceptions import AuthorizationError
from owasp_inspector.safety.authorization import ENV_FLAG, confirm_authorization, is_pre_authorized


def test_env_flag_pre_authorizes(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    assert is_pre_authorized() is True
    assert confirm_authorization("https://example.com", interactive=False) is True


def test_non_interactive_without_flag_raises(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    with pytest.raises(AuthorizationError):
        confirm_authorization("https://example.com", interactive=False)


def test_interactive_yes_confirms(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    assert confirm_authorization("https://example.com") is True


def test_interactive_no_raises(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    with pytest.raises(AuthorizationError):
        confirm_authorization("https://example.com")


def test_interactive_empty_answer_raises(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    monkeypatch.setattr("builtins.input", lambda *_: "")
    with pytest.raises(AuthorizationError):
        confirm_authorization("https://example.com")
