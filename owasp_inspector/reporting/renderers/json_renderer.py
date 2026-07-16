from __future__ import annotations

import json

from owasp_inspector.reporting.models import ReportData
from owasp_inspector.reporting.serialize import report_to_dict


def render_json(report: ReportData) -> str:
    return json.dumps(report_to_dict(report), indent=2)
