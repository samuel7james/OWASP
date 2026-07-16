import importlib

import pytest

MODULES = [
    "Scanner_vulnerability",
    "sqli_scan",
    "xss_scan",
    "csrf_scan",
    "vulnerability_scan.sqli",
    "vulnerability_scan.xss",
    "vulnerability_scan.csrf",
]


@pytest.mark.parametrize("module_name", MODULES)
def test_module_imports_cleanly(module_name):
    importlib.import_module(module_name)


def test_checker_instantiates():
    from Scanner_vulnerability import URLVulnerabilityChecker

    checker = URLVulnerabilityChecker()
    assert checker.vulnerabilities_found == []
