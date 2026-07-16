import logging
import os

from colorama import Fore, Style
from colorama import init as _colorama_init

_LEVEL_COLORS = {
    logging.DEBUG: Fore.CYAN,
    logging.INFO: Fore.WHITE,
    logging.WARNING: Fore.YELLOW,
    logging.ERROR: Fore.RED,
    logging.CRITICAL: Fore.MAGENTA,
}


class _ColorFormatter(logging.Formatter):
    def format(self, record):
        color = _LEVEL_COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{Style.RESET_ALL}" if color else message


def configure_logging(level=None):
    """Configure the root logger once. Safe to call multiple times."""
    _colorama_init()
    root = logging.getLogger()
    if root.handlers:
        return root

    resolved_level = level or os.getenv("SCAN_LOG_LEVEL", "INFO")
    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter("[%(levelname)s] %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(resolved_level)
    return root
