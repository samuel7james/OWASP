from _report_fixtures import make_finding, make_report

from owasp_inspector.cli.history import ScanHistoryStore


def test_append_and_list_round_trip(tmp_path):
    store = ScanHistoryStore(history_dir=tmp_path)
    report = make_report([make_finding()])

    entry = store.append(report, ["a.json", "a.html"])

    entries = store.list_all()
    assert len(entries) == 1
    assert entries[0] == entry
    assert entries[0].scan_id == report.scan_id
    assert entries[0].report_paths == ["a.json", "a.html"]


def test_list_all_returns_empty_when_no_history_file(tmp_path):
    store = ScanHistoryStore(history_dir=tmp_path / "does-not-exist-yet")
    assert store.list_all() == []


def test_multiple_appends_accumulate_in_order(tmp_path):
    store = ScanHistoryStore(history_dir=tmp_path)
    for i in range(3):
        report = make_report([], url=f"https://example.com/{i}")
        store.append(report, [])

    entries = store.list_all()
    assert len(entries) == 3
    assert [e.final_url for e in entries] == [
        "https://example.com/0",
        "https://example.com/1",
        "https://example.com/2",
    ]
