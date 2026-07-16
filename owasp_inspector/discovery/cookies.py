from __future__ import annotations

import http.cookies

import httpx

from owasp_inspector.discovery.models import CookieFlags


def extract_cookie_flags(response: httpx.Response) -> list[CookieFlags]:
    """Parse every Set-Cookie header on a response into its actual security
    flags. `dict(response.cookies)` (name -> value) throws this away, and
    Secure/HttpOnly/SameSite presence is exactly what A02/A07 checks need."""
    flags: list[CookieFlags] = []
    for raw in response.headers.get_list("set-cookie"):
        parsed = http.cookies.SimpleCookie()
        try:
            parsed.load(raw)
        except http.cookies.CookieError:
            continue
        for name, morsel in parsed.items():
            flags.append(
                CookieFlags(
                    name=name,
                    secure=bool(morsel["secure"]),
                    httponly=bool(morsel["httponly"]),
                    samesite=morsel["samesite"] or None,
                )
            )
    return flags
