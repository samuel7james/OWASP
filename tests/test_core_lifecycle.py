import pytest

from owasp_inspector.core.exceptions import ScanError
from owasp_inspector.core.lifecycle import Scan, ScanState


def test_happy_path_transitions():
    scan = Scan("scan-1", "https://example.com")
    assert scan.state == ScanState.QUEUED
    scan.start()
    assert scan.state == ScanState.RUNNING
    scan.complete()
    assert scan.state == ScanState.DONE
    assert scan.duration_seconds is not None


def test_pause_and_resume():
    scan = Scan("scan-2", "https://example.com")
    scan.start()
    scan.pause("rate limited")
    assert scan.state == ScanState.PAUSED
    scan.resume()
    assert scan.state == ScanState.RUNNING


def test_invalid_transition_raises():
    scan = Scan("scan-3", "https://example.com")
    with pytest.raises(ScanError):
        scan.complete()  # can't go queued -> done directly


def test_terminal_states_reject_further_transitions():
    scan = Scan("scan-4", "https://example.com")
    scan.start()
    scan.fail("boom")
    with pytest.raises(ScanError):
        scan.start()
