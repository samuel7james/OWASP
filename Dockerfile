# syntax=docker/dockerfile:1

# ---- Builder: resolve and install Python dependencies ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Only the files pip needs to resolve dependencies and build the
# owasp_inspector package/main.py module — keeps this layer cached across
# changes to Logic/UI/Data/tests, which don't affect what gets installed.
COPY pyproject.toml README.md main.py ./
COPY owasp_inspector ./owasp_inspector

RUN pip install --no-cache-dir --prefix=/install .

# ---- Runtime: slim image with only what's needed to run a scan ----
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="OWASP Inspector" \
      org.opencontainers.image.description="Automated OWASP Top 10 assessment engine: one URL, one command." \
      org.opencontainers.image.licenses="MIT"

RUN useradd --create-home --shell /bin/bash scanner
WORKDIR /app

COPY --from=builder /install /usr/local

# Logic/UI/Data are plain (non-package) source trees the legacy menu entry
# point loads via a sys.path shim at import time, not through setuptools —
# see owasp_inspector/modules/_legacy_common.py and main.py. They have to
# be copied in as files, not installed as a package, for
# `owasp-inspector-legacy-menu` to work.
COPY owasp_inspector ./owasp_inspector
COPY Logic ./Logic
COPY UI ./UI
COPY Data ./Data
COPY main.py pyproject.toml README.md ./

# Scan output directories the tool writes into at runtime (reports, caches,
# per-category result dumps) — created ahead of time so they're owned by
# the unprivileged `scanner` user rather than root.
RUN mkdir -p Data/reports Data/scan_history Data/scan_cache \
        Data/sqli_scan_results Data/xss_scan_results Data/csrf_scan_results Data/Parameters \
    && chown -R scanner:scanner /app

USER scanner

# Scans require explicit authorization; the interactive prompt doesn't work
# in a non-interactive container, so callers must set this themselves
# (`docker run -e OWASP_INSPECTOR_AUTHORIZED=1 ...`) — left unset here on
# purpose rather than defaulted to "1", so running the image doesn't
# silently imply consent.
ENTRYPOINT ["owasp-inspector"]
CMD ["--help"]
