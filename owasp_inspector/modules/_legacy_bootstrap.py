"""Adds the legacy Logic/ flat-import paths to sys.path, mirroring main.py's
bootstrap. Modules that wrap the existing SQLi/XSS/CSRF engines import this
module first (for its side effect) since those engines rely on that layout
and aren't proper importable packages yet — that migration is intentionally
deferred until the legacy engines have a reason to move beyond a thin wrap.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for _p in (
    _ROOT,
    os.path.join(_ROOT, "Logic"),
    os.path.join(_ROOT, "Logic", "Recon"),
    os.path.join(_ROOT, "Logic", "vulnerability_scan"),
    os.path.join(_ROOT, "Data"),
):
    if _p not in sys.path:
        sys.path.append(_p)
