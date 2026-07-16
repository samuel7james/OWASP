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


def _weak_protocol_context() -> ssl.SSLContext:
    # Deliberately permissive: this connection exists only to observe what
    # protocol version the *server* is willing to negotiate down to, for the
    # A02 "deprecated TLS version" check. Python's default context refuses
    # TLS 1.0/1.1 (and OpenSSL's default SECLEVEL=2 blocks the weak ciphers
    # that go with them) unconditionally — meaning without this, a server
    # that *only* speaks TLS 1.0 fails the handshake outright and the check
    # can never actually fire. This context doesn't touch any real request;
    # it's a read-only probe of a socket that's closed immediately after.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


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
    except ssl.SSLError:
        return _fetch_with_weak_protocol_fallback(hostname, port, timeout)

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


def _fetch_with_weak_protocol_fallback(hostname: str, port: int, timeout: float) -> TlsInfo:
    # Reached only when a modern-minimum handshake failed outright (not a
    # cert-trust failure) — the last real possibility worth checking before
    # giving up is that the server only speaks a deprecated protocol version.
    ctx = _weak_protocol_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            version = tls_sock.version()
    return TlsInfo(
        inspected=True,
        version=version,
        error="certificate not verifiable, and/or only a deprecated TLS version is supported",
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
