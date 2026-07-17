import os
import sys


def _configure_utf8_stdio():
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


_configure_utf8_stdio()

root = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir(os.path.join(root, "UI")):
    # A non-editable `pip install .` copies this file into site-packages,
    # disconnected from the real UI/Logic/Data siblings (which aren't
    # installable packages themselves — see pyproject.toml's ruff exclude
    # comment). Fall back to the working directory, which is where a
    # packaged deployment (e.g. the Dockerfile's WORKDIR /app) actually
    # keeps them alongside this script.
    root = os.getcwd()
sys.path.append(root)
sys.path.append(os.path.join(root, "UI"))
sys.path.append(os.path.join(root, "Logic"))
sys.path.append(os.path.join(root, "Logic", "Recon"))
sys.path.append(os.path.join(root, "Logic", "vulnerability_scan"))
sys.path.append(os.path.join(root, "Data"))

from UI.main import main

if __name__ == "__main__":
    main()
