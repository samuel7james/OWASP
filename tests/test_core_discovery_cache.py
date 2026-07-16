from owasp_inspector.core.discovery_cache import DiscoveryCache
from owasp_inspector.discovery.models import CookieFlags, DiscoveryResult, Fingerprint, ParamTarget, TlsInfo


def _discovery(url="https://example.com/"):
    return DiscoveryResult(
        target_url=url, final_url=url, ok=True, status_code=200,
        headers={"server": "nginx"}, cookies={"a": "b"},
        fingerprint=Fingerprint(technology="django", confidence="high", evidence=["x"]),
        tls=TlsInfo(inspected=True, version="TLSv1.3", subject="commonName=example.com"),
        sitemap_urls=["https://example.com/sitemap.xml"],
        crawled_urls=[url],
        targets=[ParamTarget(method="get", url=url, params=["q"])],
        cookie_flags=[CookieFlags(name="sid", secure=True, httponly=True, samesite="Lax")],
    )


def test_save_and_load_round_trips(tmp_path):
    cache = DiscoveryCache(cache_dir=tmp_path)
    original = _discovery()
    cache.save(original.final_url, original)

    loaded = cache.load(original.final_url)
    assert loaded is not None
    assert loaded.final_url == original.final_url
    assert loaded.headers == original.headers
    assert loaded.fingerprint.technology == "django"
    assert loaded.tls.version == "TLSv1.3"
    assert loaded.targets[0].params == ["q"]
    assert loaded.cookie_flags[0].secure is True


def test_load_returns_none_when_nothing_cached(tmp_path):
    cache = DiscoveryCache(cache_dir=tmp_path)
    assert cache.load("https://never-scanned.example.com/") is None


def test_load_returns_none_when_stale(tmp_path):
    cache = DiscoveryCache(cache_dir=tmp_path)
    discovery = _discovery()
    cache.save(discovery.final_url, discovery)

    assert cache.load(discovery.final_url, max_age_seconds=0.0) is None


def test_different_urls_do_not_collide(tmp_path):
    cache = DiscoveryCache(cache_dir=tmp_path)
    cache.save("https://a.example.com/", _discovery("https://a.example.com/"))
    cache.save("https://b.example.com/", _discovery("https://b.example.com/"))

    assert cache.load("https://a.example.com/").final_url == "https://a.example.com/"
    assert cache.load("https://b.example.com/").final_url == "https://b.example.com/"


def test_load_handles_corrupted_cache_file_gracefully(tmp_path):
    cache = DiscoveryCache(cache_dir=tmp_path)
    discovery = _discovery()
    cache.save(discovery.final_url, discovery)
    cache._path_for(discovery.final_url).write_text("not json at all {{{", encoding="utf-8")

    assert cache.load(discovery.final_url) is None
