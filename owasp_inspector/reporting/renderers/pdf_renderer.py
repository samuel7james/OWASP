from __future__ import annotations

import io

from owasp_inspector.core.exceptions import OwaspInspectorError
from owasp_inspector.reporting.models import ReportData
from owasp_inspector.reporting.renderers.html_renderer import render_html


class PdfRenderingError(OwaspInspectorError):
    """Raised when the optional PDF rendering dependency is missing or fails."""


def render_pdf(report: ReportData) -> bytes:
    """Render the same HTML report to PDF via xhtml2pdf (pure Python, no
    native library dependency) rather than WeasyPrint — WeasyPrint needs a
    GTK/Pango runtime that isn't pip-installable on Windows, which would make
    PDF export broken out of the box on exactly the platform this was built on.
    """
    try:
        from xhtml2pdf import pisa
    except ImportError as exc:
        raise PdfRenderingError(
            "PDF export requires the optional 'xhtml2pdf' dependency. Install with: pip install xhtml2pdf"
        ) from exc

    html = render_html(report)
    buffer = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buffer)
    if result.err:
        raise PdfRenderingError(f"PDF rendering failed with {result.err} error(s)")
    return buffer.getvalue()
