class OwaspInspectorError(Exception):
    """Base class for all errors raised by the scanning engine."""


class ConfigurationError(OwaspInspectorError):
    """Raised when required configuration is missing or invalid."""


class NetworkError(OwaspInspectorError):
    """Raised when a target cannot be reached or a request fails unrecoverably."""


class ScanError(OwaspInspectorError):
    """Raised when a scan module fails in a way that should stop that module's run."""


class AuthorizationError(OwaspInspectorError):
    """Raised when a scan is attempted without the required authorization confirmation."""
