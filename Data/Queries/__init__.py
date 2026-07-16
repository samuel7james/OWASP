# Data/Queries — active modules for SQLi/XSS/CSRF scans
from Data.Queries.q_scans import create_scan, update_scan_original_url, update_scan_status
from Data.Queries.scan_stats import ScanStats

__all__ = [
    'create_scan',
    'update_scan_status',
    'update_scan_original_url',
    'ScanStats',
]
