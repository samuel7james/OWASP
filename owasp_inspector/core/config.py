from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Canonical, typed configuration for the scanning engine.

    Every field here is actually read somewhere in `owasp_inspector/` —
    scan concurrency/timeout/pacing is controlled per-run via `--profile`
    (see `core/profiles.py`), not env vars, so there's deliberately no
    knob for it here.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # SQLi/XSS/CSRF module concurrency
    scan_sqli_workers: int = 10
    # Whether to also test session/tracking cookies normally excluded by
    # the denylist (see modules/sqli/__init__.py's _COOKIE_DENYLIST)
    scan_sqli_probe_all_cookies: bool = False


def get_settings() -> Settings:
    return Settings()
