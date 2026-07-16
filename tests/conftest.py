import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (
    _ROOT,
    os.path.join(_ROOT, "UI"),
    os.path.join(_ROOT, "Logic"),
    os.path.join(_ROOT, "Logic", "Recon"),
    os.path.join(_ROOT, "Logic", "vulnerability_scan"),
    os.path.join(_ROOT, "Data"),
):
    if _p not in sys.path:
        sys.path.append(_p)
