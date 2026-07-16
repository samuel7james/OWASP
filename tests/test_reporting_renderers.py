import json

from _report_fixtures import make_finding, make_report

from owasp_inspector.reporting.renderers.html_renderer import render_html
from owasp_inspector.reporting.renderers.json_renderer import render_json
from owasp_inspector.reporting.renderers.markdown_renderer import render_markdown
from owasp_inspector.reporting.renderers.pdf_renderer import render_pdf


def test_render_json_round_trips():
    report = make_report([make_finding(title="Reflected XSS")])
    data = json.loads(render_json(report))
    assert data["findings"][0]["title"] == "Reflected XSS"


def test_render_markdown_contains_key_sections():
    report = make_report([make_finding(title="Reflected XSS")])
    md = render_markdown(report)
    assert "# OWASP Inspector Report" in md
    assert "## Executive Summary" in md
    assert "## Findings" in md
    assert "Reflected XSS" in md
    assert "## Scan Timeline" in md


def test_render_markdown_handles_zero_findings():
    report = make_report([])
    md = render_markdown(report)
    assert "No findings." in md


def test_render_html_escapes_and_includes_findings():
    report = make_report([make_finding(title="Reflected XSS")])
    html = render_html(report)
    assert "<html" in html
    assert "Reflected XSS" in html
    assert "OWASP Inspector Report" in html


def test_render_html_escapes_untrusted_looking_content():
    report = make_report([make_finding(title="<script>alert(1)</script>")])
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_pdf_produces_valid_pdf_bytes():
    report = make_report([make_finding(title="Reflected XSS")])
    pdf_bytes = render_pdf(report)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500
