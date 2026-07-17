import pytest
from _report_fixtures import make_finding, make_scan_result
from typer.testing import CliRunner

from owasp_inspector.cli import app as cli_app
from owasp_inspector.cli.history import ScanHistoryStore

runner = CliRunner()


def test_rewrite_argv_injects_scan_for_bare_url():
    assert cli_app.rewrite_argv_for_implicit_scan(["https://example.com"]) == ["scan", "https://example.com"]


def test_rewrite_argv_injects_scan_with_trailing_options():
    result = cli_app.rewrite_argv_for_implicit_scan(["https://example.com", "--yes", "--max-pages", "1"])
    assert result == ["scan", "https://example.com", "--yes", "--max-pages", "1"]


def test_rewrite_argv_leaves_known_commands_alone():
    assert cli_app.rewrite_argv_for_implicit_scan(["history"]) == ["history"]
    assert cli_app.rewrite_argv_for_implicit_scan(["scan", "https://x"]) == ["scan", "https://x"]


def test_rewrite_argv_leaves_help_alone():
    assert cli_app.rewrite_argv_for_implicit_scan(["--help"]) == ["--help"]


def test_validate_profile_rejects_unknown():
    with pytest.raises(Exception):
        cli_app._validate_profile("nonexistent-profile")


def test_validate_formats_rejects_unknown():
    with pytest.raises(Exception):
        cli_app._validate_formats("json,not-a-real-format")


def test_validate_formats_defaults_when_empty():
    assert cli_app._validate_formats("") == ["html", "json"]


def test_scan_command_writes_reports_and_exits_zero_for_good_grade(monkeypatch, tmp_path):
    async def _fake_run_scan(url, *, profile, max_pages, resume=False, respect_robots=False):
        return make_scan_result([], url=url)

    monkeypatch.setattr(cli_app, "run_scan", _fake_run_scan)
    monkeypatch.setattr(cli_app, "ScanHistoryStore", lambda: ScanHistoryStore(history_dir=tmp_path / "history"))
    monkeypatch.setenv("OWASP_INSPECTOR_AUTHORIZED", "1")

    result = runner.invoke(
        cli_app.app,
        ["scan", "https://example.com", "--format", "json", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    written = list(tmp_path.glob("*.json"))
    assert len(written) == 1


def test_scan_command_exits_nonzero_for_bad_grade(monkeypatch, tmp_path):
    async def _fake_run_scan(url, *, profile, max_pages, resume=False, respect_robots=False):
        from owasp_inspector.core.models import Confidence, Severity

        return make_scan_result(
            [make_finding(severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED) for _ in range(5)],
            url=url,
        )

    monkeypatch.setattr(cli_app, "run_scan", _fake_run_scan)
    monkeypatch.setattr(cli_app, "ScanHistoryStore", lambda: ScanHistoryStore(history_dir=tmp_path / "history"))
    monkeypatch.setenv("OWASP_INSPECTOR_AUTHORIZED", "1")

    result = runner.invoke(
        cli_app.app,
        ["scan", "https://example.com", "--format", "json", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 2


def test_scan_command_requires_authorization(monkeypatch, tmp_path):
    monkeypatch.delenv("OWASP_INSPECTOR_AUTHORIZED", raising=False)
    monkeypatch.setattr("builtins.input", lambda *_: "n")

    result = runner.invoke(cli_app.app, ["scan", "https://example.com", "--output-dir", str(tmp_path)])

    assert result.exit_code == 1
    assert "Authorization not confirmed" in result.output


def test_scan_command_rejects_unknown_profile(tmp_path):
    result = runner.invoke(cli_app.app, ["scan", "https://example.com", "--profile", "nonexistent", "--output-dir", str(tmp_path)])
    assert result.exit_code != 0


def test_history_command_lists_past_scans(monkeypatch, tmp_path):
    store = ScanHistoryStore(history_dir=tmp_path)
    store.append(build_test_report(), ["r1.json"])
    monkeypatch.setattr(cli_app, "ScanHistoryStore", lambda: store)

    result = runner.invoke(cli_app.app, ["history"])
    assert result.exit_code == 0
    # Rich truncates long columns in the narrow test console, so check the
    # scan ID (short, never truncated) rather than the full target URL.
    assert "test-scan-id" in result.output


def test_history_command_handles_empty_history(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_app, "ScanHistoryStore", lambda: ScanHistoryStore(history_dir=tmp_path))
    result = runner.invoke(cli_app.app, ["history"])
    assert result.exit_code == 0
    assert "No scan history yet" in result.output


def build_test_report():
    from owasp_inspector.reporting.builder import build_report

    return build_report(make_scan_result([make_finding()]))
