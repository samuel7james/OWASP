import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()

from Data.Queries.q_reports import save_report as _q_reports
from Data.Queries.q_scans import create_scan as _q_create_scan
from Data.Queries.q_scans import update_scan_status as _q_update_scan


class DatabaseManager:
    def __init__(self, host=None, database=None, user=None, password=None, port=None):
        self.conn_params = {
            "host": host or os.getenv("DB_HOST", "localhost"),
            "database": database or os.getenv("DB_DATABASE", "vulnerability_scanner"),
            "user": user or os.getenv("DB_USER", "postgres"),
            "password": password or os.getenv("DB_PASSWORD", ""),
            "port": port or os.getenv("DB_PORT", "5432"),
        }
        self.conn = None

    def connect(self):
        try:
            if not self.conn or self.conn.closed:
                self.conn = psycopg2.connect(**self.conn_params, connect_timeout=3)
            return True
        except psycopg2.OperationalError:
            return False
        except Exception as e:
            print(f"[-] Database connection error: {e}")
            return False

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()

    def _execute(self, query, params=None, commit=True):
        if not self.connect():
            return None
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if commit:
                    self.conn.commit()
                if cur.description:
                    return cur.fetchone()
            return True
        except Exception as e:
            print(f"[-] DB execution error: {e}")
            if self.conn:
                self.conn.rollback()
            return None

    def _execute_all(self, query, params=None):
        if not self.connect():
            return []
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if cur.description:
                    return cur.fetchall()
            return []
        except Exception as e:
            print(f"[-] DB execution error: {e}")
            if self.conn:
                self.conn.rollback()
            return []

    def create_scan(self, scan_id, original_url, user_agent=None, cookie=None, proxy=None):
        return _q_create_scan(self, scan_id, original_url, user_agent, cookie, proxy)

    def update_scan_status(self, scan_id, status='completed', final_url=None,
                           has_waf=False, waf_vendors=None, grade=None, score=None):
        return _q_update_scan(self, scan_id, status, final_url, has_waf, waf_vendors, grade, score)

    def add_report(self, scan_id, report_type, content):
        return _q_reports(self, scan_id, report_type, content)
