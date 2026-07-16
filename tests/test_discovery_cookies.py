import httpx

from owasp_inspector.discovery.cookies import extract_cookie_flags


def test_extracts_secure_httponly_samesite():
    response = httpx.Response(200, headers=[("set-cookie", "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax")])
    flags = extract_cookie_flags(response)
    assert len(flags) == 1
    assert flags[0].name == "sessionid"
    assert flags[0].secure is True
    assert flags[0].httponly is True
    assert flags[0].samesite == "Lax"


def test_missing_flags_are_false_or_none():
    response = httpx.Response(200, headers=[("set-cookie", "tracking=xyz; Path=/")])
    flags = extract_cookie_flags(response)
    assert flags[0].secure is False
    assert flags[0].httponly is False
    assert flags[0].samesite is None


def test_multiple_set_cookie_headers_all_parsed():
    response = httpx.Response(
        200,
        headers=[
            ("set-cookie", "sessionid=abc; HttpOnly; Secure"),
            ("set-cookie", "tracking=xyz"),
        ],
    )
    flags = extract_cookie_flags(response)
    assert {f.name for f in flags} == {"sessionid", "tracking"}


def test_no_cookies_returns_empty_list():
    response = httpx.Response(200)
    assert extract_cookie_flags(response) == []


def test_malformed_cookie_header_is_skipped_not_raised():
    response = httpx.Response(200, headers=[("set-cookie", "=====not-a-cookie=====")])
    assert extract_cookie_flags(response) == []
