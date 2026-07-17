# syntax=docker/dockerfile:1

# ---- Builder: resolve and install Python dependencies ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Only the files pip needs to resolve dependencies and build the
# owasp_inspector package — keeps this layer cached across changes to
# Data/tests, which don't affect what gets installed.
COPY pyproject.toml README.md ./
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

COPY owasp_inspector ./owasp_inspector
COPY Data ./Data
COPY pyproject.toml README.md ./

# Scan output directories the tool writes into at runtime (reports,
# discovery cache, scan history) — created ahead of time so they're owned
# by the unprivileged `scanner` user rather than root.
RUN mkdir -p Data/reports Data/scan_history Data/scan_cache \
    && chown -R scanner:scanner /app

USER scanner

# Scans require explicit authorization; the interactive prompt doesn't work
# in a non-interactive container, so callers must set this themselves
# (`docker run -e OWASP_INSPECTOR_AUTHORIZED=1 ...`) — left unset here on
# purpose rather than defaulted to "1", so running the image doesn't
# silently imply consent.
ENTRYPOINT ["owasp-inspector"]
CMD ["--help"]
