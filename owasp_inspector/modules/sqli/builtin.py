from __future__ import annotations

import asyncio
import re
import time
import urllib.parse

from owasp_inspector.core.http import AsyncHttpClient
from owasp_inspector.modules.sqli.context import SqliContext
from owasp_inspector.modules.sqli.payloads import SqliPayload

# Cookies that are framework/session/tracking artefacts, not user-controlled
# query inputs — excluded from the cookie-based injection surface, same
# denylist as the legacy engine (ported verbatim).
_COOKIE_DENYLIST = (
    "sessid",
    "sessionid",
    "phpsessid",
    "jsessionid",
    "aspsession",
    "asp.net",
    "csrf",
    "xsrf",
    "_token",
    "laravel_session",
    "remember_",
    "device_",
    "uuid",
    "ts0",
    "cf_",
    "__cf",
    "ak_bmsc",
    "incap_",
    "visid",
    "bm_",
    "_ga",
    "_gid",
    "_gcl",
    "gtm",
    "fbp",
    "fbclid",
    "amplitude",
    "mp_",
    "default_language",
    "locale",
    "timezone",
    "consent",
)

_AUTH_SUCCESS_PATHS = ("/my-account", "/account", "/dashboard", "/profile")
_AUTH_SUCCESS_BODY_INDICATORS = (
    "logout",
    "log out",
    "sign out",
    "logged in as",
    "your username is",
    "change email",
    "update email",
    "my account",
)
_SIZE_DIFF_EXCLUDED_TYPES = (
    "time",
    "union",
    "auth bypass",
    "order by",
    "version",
    "extractvalue",
    "complex",
    "mssql",
    "mysql",
    "oracle",
    "postgresql",
)


def _auth_success_signal(response, baseline_text: str = "", baseline_url: str = "") -> tuple[bool, str]:
    if not response:
        return False, ""
    resp_lower = (response.text or "").lower()
    baseline_lower = (baseline_text or "").lower()
    final_path = urllib.parse.urlparse(str(response.url)).path.lower().rstrip("/")
    base_path = urllib.parse.urlparse(str(baseline_url or "")).path.lower().rstrip("/")

    if final_path and final_path != base_path:
        for path in _AUTH_SUCCESS_PATHS:
            if final_path == path or final_path.startswith(path + "/"):
                return True, f"final URL path changed to {final_path}"

    for indicator in _AUTH_SUCCESS_BODY_INDICATORS:
        if indicator in resp_lower and indicator not in baseline_lower:
            return True, f'strong auth indicator "{indicator}" appeared'

    return False, ""


class BuiltinSqliScanner:
    """Async port of Logic/vulnerability_scan/sqli/scanners/builtin.py.

    Every detection check (error pattern, UNION reflection, version
    extraction, UNION column-count, time-based double-confirmation,
    auth-bypass with control-request verification, size-diff, boolean
    toggle) and every false-positive filter is preserved as-is — this is a
    faithful port of the I/O layer to native async, not a reimplementation
    of the detection logic, which was already tuned and working.
    """

    def __init__(self, http: AsyncHttpClient, sqli_ctx: SqliContext, *, max_concurrency: int = 10):
        self.http = http
        self.ctx = sqli_ctx
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def scan(self, targets: list[tuple[str, dict]]) -> tuple[list[dict], list[dict]]:
        """`targets` is a list of (method, target_dict) where target_dict has
        keys url/params/defaults, matching the legacy shape so the ported
        detection logic below needs no changes."""
        vulns: list[dict] = []
        candidates: list[dict] = []

        if not targets:
            return vulns, candidates

        base_resp = await self.ctx.make_request(targets[0][1]["url"])
        waf_name = self.ctx.detect_waf(base_resp)
        if waf_name:
            print(f"    [WARN] {waf_name} WAF detected. Expect many false positives or blocked requests.")

        tasks = await self._build_tasks(targets)
        if not tasks:
            return vulns, candidates

        results = await asyncio.gather(*(self._worker(t) for t in tasks))

        results_map: dict[tuple, dict] = {}
        all_results: list[dict] = []
        column_map: dict[str, list[dict]] = {}
        auth_indicator_counts: dict[str, int] = {}
        size_freq: dict[int, int] = {}

        for res in results:
            if not res:
                continue
            rt = res["res_type"]
            if rt == "confirmed":
                v = res["vuln"]
                v["status"] = "confirmed"
                if not any(ev["parameter"] == v["parameter"] and ev["type"] == v["type"] for ev in vulns):
                    vulns.append(v)
            elif rt == "boolean_collect":
                key = (res["param"], res["group"])
                results_map.setdefault(key, {})[res["expected"]] = res
            elif rt == "column_collect":
                column_map.setdefault(res["param"], []).append(res)
                self._track_auth_indicators(res["r"].text, auth_indicator_counts)
            elif rt == "size_collect":
                all_results.append(res)
                size_freq[res["size"]] = size_freq.get(res["size"], 0) + 1
                self._track_auth_indicators(res["r"].text, auth_indicator_counts)
            elif rt == "candidate":
                candidates.append(res["candidate"])

        self._evaluate_size_diffs(all_results, size_freq, vulns, candidates)
        self._evaluate_boolean_toggles(results_map, vulns, candidates)
        self._evaluate_column_counts(column_map, vulns)
        self._filter_common_auth_fps(vulns, auth_indicator_counts, len(tasks))

        return vulns, candidates

    # ── task building ────────────────────────────────────────────────

    async def _build_tasks(self, targets: list[tuple[str, dict]]) -> list[dict]:
        tasks = []
        for method, target in targets:
            turl = target["url"]
            params = target["params"]
            defaults = dict(target.get("defaults", {}))
            page_url = target.get("page_url") or turl

            if method == "post":
                defaults = await self.ctx.refresh_csrf(page_url, defaults)

            base_times, base_len, baseline_url, baseline_text, base_status = [], 0, turl, "", 200
            for _ in range(2):
                t0 = time.time()
                bl = await self.ctx.send_request(method, turl, defaults)
                if bl:
                    # Measured directly rather than via response.elapsed: that
                    # property depends on transport-level instrumentation that
                    # httpx.MockTransport doesn't populate (raises RuntimeError),
                    # found via this module's own test suite. A manual timer
                    # works identically against any transport, real or mocked.
                    base_times.append(time.time() - t0)
                    base_len = len(bl.text)
                    baseline_url = str(bl.url)
                    baseline_text = bl.text
                    base_status = bl.status_code
            base_time = max(base_times) if base_times else 1.0

            for param in params:
                if param.lower() in {"csrf", "csrftoken", "csrf_token", "_csrf", "_token", "csrfmiddlewaretoken"}:
                    continue
                if method == "cookie" and param.lower() == "session" and len(defaults.get(param, "")) > 20:
                    continue
                if method == "cookie" and defaults.get(param, "") == "":
                    continue

                is_auth_target = self.ctx.is_likely_auth_target(method, turl, param, defaults)

                for p in self.ctx.payloads.payloads:
                    if "auth bypass" in p.type.lower() and not is_auth_target:
                        continue
                    clean_payload = p.payload.replace("+", " ")
                    variants = [clean_payload]
                    orig_val = str(defaults.get(param, ""))
                    if orig_val and orig_val != "FUZZ" and not clean_payload.startswith(orig_val):
                        variants.append(orig_val + clean_payload)

                    for p_val in variants:
                        test_data = {**defaults, param: p_val}
                        tasks.append(
                            {
                                "method": method,
                                "turl": turl,
                                "param": param,
                                "p": p,
                                "test_data": test_data,
                                "baseline_url": baseline_url,
                                "base_len": base_len,
                                "base_time": base_time,
                                "baseline_text": baseline_text,
                                "base_status": base_status,
                                "defaults": defaults,
                                "page_url": page_url,
                            }
                        )
        return tasks

    # ── worker ───────────────────────────────────────────────────────

    async def _worker(self, task: dict) -> dict | None:
        async with self._semaphore:
            return await self._run_one(task)

    async def _run_one(self, task: dict) -> dict | None:
        method, turl, param = task["method"], task["turl"], task["param"]
        p: SqliPayload = task["p"]
        test_data, defaults, page_url = task["test_data"], task["defaults"], task["page_url"]
        baseline_url, base_len = task["baseline_url"], task["base_len"]
        base_time, baseline_text, base_status = task["base_time"], task["baseline_text"], task["base_status"]

        payload, ptype = p.payload, p.type
        is_time_based = "time-based" in ptype
        is_auth_bypass = "auth bypass" in ptype.lower()

        try:
            req_timeout = 20.0 if is_time_based else 10.0
            if method == "post":
                payload_value = test_data.get(param, payload)
                test_data = await self.ctx.refresh_csrf(page_url, test_data)
                test_data[param] = payload_value

            t0 = time.time()
            r = await self.ctx.send_request(method, turl, test_data, timeout=req_timeout)
            elapsed = time.time() - t0
            if not r:
                return None

            res_size = len(r.text)

            if self.ctx.detect_waf(r):
                return {"res_type": "waf_block", "param": param, "size": res_size}

            for pattern in self.ctx.payloads.error_patterns:
                # Found via live testing against a real target (DVWA, uninitialized
                # DB): the baseline response for THIS param can already contain a
                # DB error unrelated to the payload (here, from the *other*
                # parameter's empty default) — every payload then "matches" the
                # same pre-existing error, a false-positive storm. Require the
                # pattern to be absent from baseline_text, exactly like the
                # reflection check below already does.
                if re.search(pattern, r.text, re.I) and not re.search(pattern, baseline_text or "", re.I):
                    return {
                        "res_type": "confirmed",
                        "vuln": self.ctx.make_vuln_dict(
                            f"{ptype} - Error Pattern Match",
                            param,
                            payload,
                            f"Found SQL error pattern: {pattern}",
                            turl,
                            method,
                        ),
                    }

            reflection = p.reflection
            if reflection and reflection in r.text and reflection not in (baseline_text or ""):
                clean_text = self.ctx.strip_payload_echoes(r.text, payload, reflection)
                if reflection in clean_text:
                    if await self.ctx.reflection_control_matches(
                        method,
                        turl,
                        param,
                        defaults,
                        reflection,
                        timeout=req_timeout,
                        payload=payload,
                    ):
                        return {
                            "res_type": "candidate",
                            "candidate": {
                                **self.ctx.make_vuln_dict(
                                    ptype,
                                    param,
                                    payload,
                                    f"Reflection marker '{reflection}' also appears with benign control input",
                                    turl,
                                    method,
                                    "low",
                                ),
                                "status": "candidate",
                            },
                        }
                    return {
                        "res_type": "confirmed",
                        "vuln": self.ctx.make_vuln_dict(
                            ptype,
                            param,
                            payload,
                            f"Target string '{reflection}' successfully reflected in response via UNION",
                            turl,
                            method,
                        ),
                    }

            if "version" in ptype.lower() or "@@version" in payload.lower() or "version()" in payload.lower():
                ver_vuln = self._check_version_extraction(r, payload, param, ptype, turl, method, baseline_text)
                if ver_vuln:
                    return ver_vuln

            if ptype == "UNION column count probing":
                return {
                    "res_type": "column_collect",
                    "param": param,
                    "columns": p.columns,
                    "status": r.status_code,
                    "errored": self.ctx.detect_sql_errors(r.text),
                    "payload": payload,
                    "method": method,
                    "turl": turl,
                    "size": res_size,
                    "r": r,
                }

            time_vuln = await self._check_time_based(
                is_time_based,
                elapsed,
                base_time,
                req_timeout,
                method,
                turl,
                test_data,
                defaults,
                param,
                ptype,
                payload,
                page_url,
            )
            if time_vuln:
                return time_vuln

            if is_auth_bypass:
                auth_vuln = await self._check_auth_bypass(
                    r,
                    baseline_text,
                    baseline_url,
                    method,
                    param,
                    ptype,
                    payload,
                    turl,
                    defaults,
                    page_url,
                )
                if auth_vuln:
                    return auth_vuln

            if baseline_url and method != "cookie" and is_auth_bypass:
                redir_vuln = self._check_redirect_auth(
                    r, baseline_text, baseline_url, param, ptype, payload, turl, method
                )
                if redir_vuln:
                    return redir_vuln

            if r.status_code >= 500 and base_status == 200 and "error-based" in ptype.lower():
                return {
                    "res_type": "confirmed",
                    "vuln": self.ctx.make_vuln_dict(
                        ptype,
                        param,
                        payload,
                        f"Payload triggered HTTP 500 error (Baseline was {base_status})",
                        turl,
                        method,
                        "high",
                    ),
                }

            if p.group:
                return {
                    "res_type": "boolean_collect",
                    "param": param,
                    "group": p.group,
                    "expected": p.expected,
                    "size": res_size,
                    "r": r,
                    "ptype": ptype,
                }

            return {
                "res_type": "size_collect",
                "param": param,
                "ptype": ptype,
                "size": res_size,
                "base_len": base_len,
                "payload": payload,
                "turl": turl,
                "method": method,
                "r": r,
            }
        except Exception:
            return None

    # ── individual check helpers ─────────────────────────────────────

    def _check_version_extraction(self, r, payload, param, ptype, turl, method, baseline_text):
        m = re.search(r"(\d+\.\d+\.\d+|MySQL|MariaDB|Ubuntu|Debian|MSSQL|Microsoft SQL Server)", r.text, re.I)
        if not m or m.group(0) in (baseline_text or ""):
            return None
        ver_str = m.group(0)
        ctx_match = re.search(r"(.{0,30}" + re.escape(ver_str) + r".{0,30})", r.text, re.S)
        if ctx_match:
            ctx = ctx_match.group(1).lower()
            if any(ext in ctx for ext in [".js", ".css", ".png", "jquery", "scripts/"]):
                return None
            ver_str = ctx_match.group(1).strip()
        return {
            "res_type": "confirmed",
            "vuln": self.ctx.make_vuln_dict(
                ptype,
                param,
                payload,
                f"Extracted version info: {ver_str}",
                turl,
                method,
            ),
        }

    async def _check_time_based(
        self,
        is_time_based,
        elapsed,
        base_time,
        req_timeout,
        method,
        turl,
        test_data,
        defaults,
        param,
        ptype,
        payload,
        page_url,
    ):
        if not is_time_based:
            return None
        threshold = max(base_time * 2, base_time + 5.0)
        if elapsed <= threshold:
            return None

        timeout2 = max(req_timeout, threshold + 15)

        confirm_data = dict(test_data)
        if method == "post":
            confirm_data = await self.ctx.refresh_csrf(page_url or turl, confirm_data)
        t1 = time.time()
        r2 = await self.ctx.send_request(method, turl, confirm_data, timeout=timeout2)
        elapsed2 = time.time() - t1
        if not r2 or elapsed2 <= threshold:
            return None

        control_data = dict(defaults)
        if method == "post":
            control_data = await self.ctx.refresh_csrf(page_url or turl, control_data)
        control_data[param] = "1SafeControl9"
        tc = time.time()
        await self.ctx.send_request(method, turl, control_data, timeout=timeout2)
        elapsed_ctrl = time.time() - tc

        if elapsed_ctrl > threshold * 0.5:
            return None

        evidence = (
            f"Time delay {elapsed:.1f}s + {elapsed2:.1f}s vs control {elapsed_ctrl:.1f}s (baseline {base_time:.1f}s)"
        )
        return {"res_type": "confirmed", "vuln": self.ctx.make_vuln_dict(ptype, param, payload, evidence, turl, method)}

    async def _check_auth_bypass(
        self, r, baseline_text, baseline_url, method, param, ptype, payload, turl, defaults, page_url
    ):
        success, evidence = _auth_success_signal(r, baseline_text, baseline_url)
        if not success:
            return None

        control_data = dict(defaults)
        if method == "post":
            control_data = await self.ctx.refresh_csrf(page_url or turl, control_data)
        control_data[param] = "ScannerControl123"
        control = await self.ctx.send_request(method, turl, control_data, timeout=10.0)
        control_success, _ = _auth_success_signal(control, baseline_text, baseline_url)
        if control_success:
            return None

        return {
            "res_type": "confirmed",
            "vuln": self.ctx.make_vuln_dict(
                f"Auth Bypass - {ptype}",
                param,
                payload,
                f"Auth success confirmed: {evidence}",
                turl,
                method,
            ),
        }

    def _check_redirect_auth(self, r, baseline_text, baseline_url, param, ptype, payload, turl, method):
        success, evidence = _auth_success_signal(r, baseline_text, baseline_url)
        if success:
            return {
                "res_type": "confirmed",
                "vuln": self.ctx.make_vuln_dict(
                    f"Auth Bypass - {ptype}",
                    param,
                    payload,
                    f"URL/body auth success after redirect: {evidence}",
                    turl,
                    method,
                ),
            }
        return None

    # ── post-processing ──────────────────────────────────────────────

    @staticmethod
    def _track_auth_indicators(text, counter):
        text_lower = text.lower()
        for indicator in ("my-account", "welcome", "logout", "dashboard"):
            if indicator in text_lower:
                counter[indicator] = counter.get(indicator, 0) + 1

    @staticmethod
    def _evaluate_size_diffs(all_results, size_freq, vulns, candidates):
        for res in all_results:
            if any(x in res["ptype"].lower() for x in _SIZE_DIFF_EXCLUDED_TYPES):
                continue
            size, base_len = res["size"], res["base_len"]
            diff = abs(size - base_len)
            if not (diff > 150 and diff > base_len * 0.08 and diff < max(base_len, size) * 0.98):
                continue
            freq_limit = 10 if diff > base_len * 0.50 else 4
            if size_freq.get(size, 0) > freq_limit:
                continue

            if diff > 1500 and diff > base_len * 0.20:
                vulns.append(
                    {
                        "type": f"SQL Injection ({res['ptype']})",
                        "parameter": res["param"],
                        "payload": res["payload"],
                        "evidence": f"Massive response size diff: {diff} bytes ({base_len}->{size})",
                        "tool": "builtin_sqli",
                        "confidence": "high",
                        "status": "confirmed",
                        "url": res["turl"],
                        "method": res["method"],
                    }
                )
            else:
                candidates.append(
                    {
                        "type": f"SQL Injection ({res['ptype']})",
                        "parameter": res["param"],
                        "payload": res["payload"],
                        "evidence": f"Response size diff: {diff} bytes ({base_len}->{size})",
                        "tool": "builtin_sqli",
                        "confidence": "low",
                        "status": "candidate",
                        "url": res["turl"],
                        "method": res["method"],
                    }
                )

    @staticmethod
    def _evaluate_boolean_toggles(results_map, vulns, candidates):
        for (param, _group), data in results_map.items():
            if "true" not in data or "false" not in data:
                continue
            true_res, false_res = data["true"], data["false"]
            diff = abs(true_res["size"] - false_res["size"])
            larger = max(true_res["size"], false_res["size"])
            if not (diff > 300 and diff > true_res["size"] * 0.15 and diff < larger * 0.95):
                continue

            if diff > 5000:
                vulns.append(
                    {
                        "type": f"SQL Injection ({true_res['ptype']})",
                        "parameter": param,
                        "payload": f"{data['true']['group']} (T/F toggled)",
                        "evidence": f"High-confidence Boolean TRUE/FALSE size difference: {diff} bytes",
                        "tool": "builtin_sqli",
                        "confidence": "high",
                        "status": "confirmed",
                        "url": str(true_res["r"].url),
                        "method": "mixed",
                    }
                )
            else:
                candidates.append(
                    {
                        "type": f"SQL Injection ({true_res['ptype']})",
                        "parameter": param,
                        "payload": f"{data['true']['group']} (T/F toggled)",
                        "evidence": f"Boolean TRUE/FALSE size difference: {diff} bytes (>{true_res['size'] * 0.15:.0f}b threshold)",
                        "tool": "builtin_sqli",
                        "confidence": "medium",
                        "status": "suspected",
                        "url": str(true_res["r"].url),
                        "method": "mixed",
                    }
                )

    @staticmethod
    def _evaluate_column_counts(column_map, vulns):
        for param, results in column_map.items():
            successes = [r for r in results if r["status"] == 200 and not r["errored"]]
            failures = [r for r in results if r["status"] != 200 or r["errored"]]
            if not successes or (not failures and len(successes) >= 3):
                continue
            if len(successes) >= len(results) - 1 and len(results) > 3:
                continue
            for s in successes:
                if any(
                    v.get("type") == "SQL Injection (UNION Column Count)"
                    and v.get("parameter") == param
                    and v.get("payload") == s["payload"]
                    for v in vulns
                ):
                    continue
                vulns.append(
                    {
                        "type": "SQL Injection (UNION Column Count)",
                        "parameter": param,
                        "payload": s["payload"],
                        "evidence": f"Correct column count found: {s['columns']} columns (Confirmed via transition from error)",
                        "tool": "builtin_sqli",
                        "confidence": "high",
                        "status": "confirmed",
                        "url": s["turl"],
                        "method": s["method"],
                    }
                )

    @staticmethod
    def _filter_common_auth_fps(vulns, auth_indicator_counts, total_tasks):
        if not auth_indicator_counts:
            return
        bad = {ind for ind, cnt in auth_indicator_counts.items() if cnt > total_tasks * 0.7}
        if not bad:
            return
        vulns[:] = [
            v
            for v in vulns
            if not ("Auth Bypass" in v["type"] and any(ind.lower() in v.get("evidence", "").lower() for ind in bad))
        ]
