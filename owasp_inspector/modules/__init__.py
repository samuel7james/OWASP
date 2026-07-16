"""Importing this package registers every built-in assessment module with
owasp_inspector.core.registry.default_registry. New categories are added by
creating a module file here decorated with @register_module and importing
it below — the core engine never needs to know about it directly.
"""

from owasp_inspector.modules import (  # noqa: F401
    csrf,
    idor,
    misconfiguration,
    sqli,
    ssrf,
    vulnerable_components,
    xss,
)
