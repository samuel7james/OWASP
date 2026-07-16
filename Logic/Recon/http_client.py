import os
import urllib.parse

import httpx
from env_utils import env_bool
from user_agents import UA_POOL as _UA_POOL
from user_agents import default_ua_header as _default_ua

UA = {'User-Agent': _UA_POOL[0]}
HTTP_TIMEOUT = float(os.getenv("SCAN_RECON_TIMEOUT", "30"))
CONNECT_TIMEOUT = float(os.getenv("SCAN_CONNECT_TIMEOUT", "15"))
_PROXY_CACHE = {"checked": False, "value": None}


def _candidate_urls(url: str) -> list[str]:
    """Return URL variants to try (original, scheme flip for http-only targets)."""
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    if not parsed.netloc:
        return [url]
    path = parsed.path or "/"
    base = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))
    candidates = [base]
    if parsed.scheme == "http":
        alt = urllib.parse.urlunparse(("https", parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))
        candidates.append(alt)
    return candidates


def probe_target(url, cookie=None, timeout=None):
    """
    Check whether a target responds. Tries http/https and httpx/requests fallbacks.
    Returns {ok, final_url, status_code, error}.
    """

    timeout = float(timeout or HTTP_TIMEOUT)
    connect = min(float(os.getenv("SCAN_PROBE_CONNECT_TIMEOUT", "15")), timeout)
    headers = {**_default_ua(), **({"Cookie": cookie} if cookie else {})}
    last_error = "unknown error"

    for attempt_url in _candidate_urls(url):
        for use_httpx in (True, False):
            try:
                if use_httpx:
                    with httpx.Client(
                        verify=False,
                        timeout=httpx.Timeout(connect, read=timeout),
                        follow_redirects=True,
                        headers=headers,
                        http2=False,
                    ) as client:
                        resp = client.get(attempt_url)
                        final_url = str(resp.url)
                        status = resp.status_code
                else:
                    import requests

                    resp = requests.get(
                        attempt_url,
                        timeout=(connect, timeout),
                        verify=False,
                        allow_redirects=True,
                        headers=headers,
                    )
                    final_url = resp.url
                    status = resp.status_code
                if status:
                    return {
                        "ok": True,
                        "final_url": final_url,
                        "status_code": status,
                        "error": None,
                    }
            except Exception as exc:
                last_error = str(exc)

    return {
        "ok": False,
        "final_url": url,
        "status_code": None,
        "error": last_error,
    }

class ReconHttpClient:
    """Handles HTTP connections and proxy configuration for reconnaissance."""

    @staticmethod
    def find_proxy():
        manual_proxy = os.getenv("SCAN_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        if manual_proxy:
            return manual_proxy

        if not env_bool("SCAN_AUTO_PROXY", False):
            return None

        if _PROXY_CACHE["checked"]:
            return _PROXY_CACHE["value"]

        for port in (8080, 8081):
            proxy_url = f"http://127.0.0.1:{port}"
            try:
                with httpx.Client(proxy=proxy_url, timeout=2.0, verify=False, trust_env=False) as client:
                    client.get("http://example.com", timeout=2.0)
                _PROXY_CACHE["checked"] = True
                _PROXY_CACHE["value"] = proxy_url
                print(f"[+] Proxy detected on port {port}")
                return proxy_url
            except Exception:
                continue

        _PROXY_CACHE["checked"] = True
        _PROXY_CACHE["value"] = None
        return None

    @staticmethod
    def build_client(cookie=None, cookies_dict=None, follow_redirects=False):
        proxy = ReconHttpClient.find_proxy()
        request_headers = {**_default_ua(), **({'Cookie': cookie} if cookie else {})}
        
        params = {
            "timeout": httpx.Timeout(HTTP_TIMEOUT),
            "follow_redirects": follow_redirects,
            "verify": False,
            "http2": False,
            "headers": request_headers,
            "cookies": cookies_dict,
            "limits": httpx.Limits(max_connections=20, max_keepalive_connections=10),
            "trust_env": not bool(proxy),
        }
        if proxy:
            params["proxy"] = proxy
        return httpx.Client(**params)

    @staticmethod
    def build_bypass_client(waf_result, cookie=None):
        """Create a WafBypassClient when a WAF has been detected.

        Parameters
        ----------
        waf_result : dict
            Output from ``WafDetector.detect_waf()``.
        cookie : str | None
            Session cookie string to carry into bypass requests.

        Returns
        -------
        WafBypassClient | None
            A bypass client ready to use, or None if bypass is unavailable
            or no WAF was detected.
        """
        from Logic.Recon.waf_bypass import create_bypass_client
        proxy = ReconHttpClient.find_proxy()
        return create_bypass_client(waf_result, cookie=cookie, proxy=proxy)
