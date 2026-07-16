from __future__ import annotations

import asyncio
import socket
import ssl
import urllib.parse

from owasp_inspector.discovery.models import TlsInfo


def _name(entries) -> str | None:
    if not entries:
        return None
    parts = [f"{k}={v}" for rdn in entries for (k, v) in rdn]
    return ", ".join(parts) or None


def _fetch_cert_sync(hostname: str, port: int, timeout: float) -> TlsInfo:
    # Verify first so valid certs yield full parsed fields — getpeercert() only
    # returns parsed subject/issuer/expiry when the chain actually validated;
    # with CERT_NONE it silently comes back empty even on a successful handshake.
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                version = tls_sock.version()
        return TlsInfo(
            inspected=True,
            version=version,
            subject=_name(cert.get("subject")),
            issuer=_name(cert.get("issuer")),
            not_after=cert.get("notAfter"),
        )
    except ssl.SSLCertVerificationError:
        pass

    # Self-signed/expired/hostname-mismatched cert — common on labs and internal
    # targets. Still confirm TLS reachability/version; flag the trust failure
    # itself as evidence rather than silently reporting nothing.
    insecure_ctx = ssl.create_default_context()
    insecure_ctx.check_hostname = False
    insecure_ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with insecure_ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            version = tls_sock.version()
    return TlsInfo(
        inspected=True,
        version=version,
        error="certificate not verifiable (self-signed, expired, or hostname mismatch)",
    )


async def inspect_tls(url: str, timeout: float = 10.0) -> TlsInfo:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        return TlsInfo(inspected=False)

    hostname = parsed.hostname
    if not hostname:
        return TlsInfo(inspected=False, error="no hostname in URL")

    port = parsed.port or 443
    try:
        return await asyncio.to_thread(_fetch_cert_sync, hostname, port, timeout)
    except (TimeoutError, ssl.SSLError, OSError) as exc:
        return TlsInfo(inspected=False, error=str(exc))
