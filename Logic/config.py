from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Canonical, typed configuration for the scanning engine.

    This supersedes ad-hoc `os.getenv(...)` calls for any new code (Phase 3+
    core engine and OWASP modules). Existing legacy scanner modules still read
    `os.getenv` directly and are migrated to this in Phase 5 alongside their
    move into the new module system, to avoid touching each file twice.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database (optional — scans work without Postgres configured)
    db_host: str = "localhost"
    db_database: str = "vulnerability_scanner"
    db_user: str = "postgres"
    db_password: str = ""
    db_port: str = "5432"

    # HTTP / crawl tuning
    scan_http_timeout: float = 30.0
    scan_http_timeout_retry: float = 60.0
    scan_jitter: float = 0.0
    scan_crawl_timeout: float = 10.0
    scan_crawl_threads: int = 8
    scan_crawl_limit: int = 40
    scan_param_link_limit: int = 200
    scan_training_crawl_limit: int = 40
    scan_recon_timeout: float = 30.0
    scan_connect_timeout: float = 15.0
    scan_probe_connect_timeout: float = 15.0
    scan_request_delay: float = 0.0
    scan_backoff_seconds: float = 0.0

    # Proxy
    scan_proxy: str = ""
    scan_auto_proxy: bool = False

    # SQLi
    scan_sqli_workers: int = 10
    scan_sqli_probe_all_cookies: bool = False

    # Reporting
    scan_show_candidates: bool = False

    # CSRF authenticated-scan credentials (primary and second account, for
    # cross-session/IDOR-style CSRF checks)
    csrf_user: str = ""
    csrf_pass: str = ""
    csrf_user2: str = ""
    csrf_pass2: str = ""


def get_settings() -> Settings:
    return Settings()
