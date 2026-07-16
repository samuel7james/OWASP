from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from owasp_inspector.core.models import Finding
from owasp_inspector.reporting.models import ReportData

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

# Always escape: this environment only ever renders the one HTML report
# template, so there's no case where unescaped output is wanted. (Using
# select_autoescape(["html"]) here was a bug — it decides based on the
# template *filename* ending in .html, and this template is named
# report.html.jinja2, so it never actually matched and autoescaping was
# silently off. Finding titles/evidence come from scanned target content,
# so unescaped output would let a target inject markup into the report.)
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=True,
)


def _group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.owasp_category, []).append(finding)
    return dict(sorted(grouped.items()))


def render_html(report: ReportData) -> str:
    template = _env.get_template("report.html.jinja2")
    return template.render(report=report, findings_by_category=_group_by_category(report.findings))
