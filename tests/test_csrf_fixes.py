import os

from vulnerability_scan.csrf import ResultSaver
from vulnerability_scan.csrf.csrf_scanner import CSRFScanner
from vulnerability_scan.csrf.patterns import CSRF_ERROR_RE, NON_STATE_CHANGING_PATHS, SUCCESS_RE


def test_csrf_error_pattern_matches_known_rejection_text():
    assert CSRF_ERROR_RE.search("403 Forbidden: invalid csrf token")


def test_success_pattern_matches_known_success_text():
    assert SUCCESS_RE.search("Your profile updated successfully")


def test_non_state_changing_paths_include_auth_and_registration_routes():
    for path in ("/login", "/register", "/signup", "/reset-password"):
        assert path in NON_STATE_CHANGING_PATHS


def test_authenticator_receives_correct_timeout_and_second_credentials():
    scanner = CSRFScanner(
        timeout=42,
        credentials={"username": "a", "password": "b"},
        second_credentials={"username": "c", "password": "d"},
    )
    assert scanner.authenticator.timeout == 42
    assert scanner.authenticator.second_credentials == {"username": "c", "password": "d"}


def test_result_saver_writes_under_repo_root_data_dir(tmp_path, monkeypatch):
    captured = {}

    def _fake_makedirs(path, exist_ok=False):
        captured["dir"] = path

    monkeypatch.setattr(os, "makedirs", _fake_makedirs)
    monkeypatch.setattr("builtins.open", lambda *a, **kw: open(tmp_path / "results.txt", "a", encoding="utf-8"))

    ResultSaver.save(["dummy finding"])

    repo_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(
            __import__("vulnerability_scan.csrf", fromlist=["x"]).__file__
        ))))
    )
    expected_dir = os.path.join(repo_root, "Data", "csrf_scan_results")
    assert os.path.normpath(captured["dir"]) == os.path.normpath(expected_dir)
    assert "Logic" not in os.path.relpath(captured["dir"], repo_root).split(os.sep)
