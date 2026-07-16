import os


def env_float(name, default=0.0):
    try:
        return float(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


def env_bool(name, default=False):
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "enable", "enabled"}
