from __future__ import annotations

import asyncio
import random
import string

from owasp_inspector.modules.xss.context import XssContext

_CANARY_PREFIX = "xSsT3sT"


def _new_canary() -> str:
    return _CANARY_PREFIX + "".join(random.choices(string.ascii_lowercase, k=6))


class ReflectedXssScanner:
    """Async port of Logic/vulnerability_scan/xss/scanners/reflected.py.
    Both the standard payload sweep and the context-aware follow-up
    (JS-string / event-handler / attribute-breakout payloads chosen based on
    where the canary landed) are preserved as-is — a faithful I/O-layer
    translation, not a reimplementation of the classification logic.
    """

    def __init__(self, ctx: XssContext, *, max_concurrency: int = 10):
        self.ctx = ctx
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def scan(self, targets: list[tuple[str, dict]]) -> list[dict]:
        if not targets or not self.ctx.payloads.xss_payloads:
            return []

        canary = _new_canary()
        tasks = []
        for method, target in targets:
            for param in target["params"]:
                for payload_tpl, ptype in self.ctx.payloads.xss_payloads:
                    payload = payload_tpl.replace("{c}", canary)
                    tasks.append((method, target, param, payload, ptype))

        results = await asyncio.gather(*(self._probe(t, canary) for t in tasks))

        vulns: list[dict] = []
        for res in results:
            if res and not any(
                v["parameter"] == res["parameter"] and v["url"] == res["url"] and v["method"] == res["method"]
                for v in vulns
            ):
                vulns.append(res)
        return vulns

    async def _probe(self, task: tuple, canary: str) -> dict | None:
        method, target, param, payload, ptype = task
        async with self._semaphore:
            try:
                r = await self.ctx.send_injected_request(target, method, param, payload)
                if not r:
                    return None

                hit = self.ctx.detect_active_context(r.text, canary)
                exact_match = self.ctx.body_contains_payload(r.text, payload)
                dangerous = self.ctx.payload_dangerous_constructs_survived(r.text, payload)
                scored = self.ctx.classify_reflection_result(ptype, hit, exact_match, dangerous)
                if not scored:
                    return None
                confidence, status = scored
                return {
                    "type": f"XSS (Reflected - {ptype})",
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Canary {canary} reflected in {hit.get('context', 'response')}",
                    "tool": "xsstrike_reflected",
                    "confidence": confidence,
                    "status": status,
                    "url": target["url"],
                    "method": method,
                }
            except Exception:
                return None

    async def scan_context_aware(self, targets: list[tuple[str, dict]], already_found: list[dict]) -> list[dict]:
        """Second pass: for each param not already flagged, inject a canary to
        learn the reflection context, then — only for JS-string/event-handler/
        attribute contexts — try context-specific payloads and confirm the
        payload itself (not just the canary) survives verbatim."""
        if not targets:
            return []

        canary = _new_canary()
        found: list[dict] = []

        for method, target in targets:
            for param in target["params"]:
                if any(
                    v["parameter"] == param and v["url"] == target["url"] and v["method"] == method
                    for v in already_found + found
                ):
                    continue

                try:
                    r = await self.ctx.send_injected_request(target, method, param, canary)
                    if not r or canary not in r.text:
                        continue

                    hit = self.ctx.detect_active_context(r.text, canary)
                    if not hit:
                        continue

                    ctx_name = hit.get("context", "").lower()
                    context_payloads = []
                    if "<script>" in ctx_name or "js-context" in ctx_name:
                        context_payloads = self.ctx.payloads.js_context_payloads
                    elif "handler" in ctx_name:
                        context_payloads = self.ctx.payloads.onclick_bypass_payloads
                    elif "html attribute" in ctx_name or "href" in ctx_name:
                        context_payloads = self.ctx.payloads.attribute_escape_payloads

                    if not context_payloads:
                        continue

                    for payload_tpl, ptype in context_payloads:
                        payload = payload_tpl.replace("{c}", canary)
                        try:
                            r2 = await self.ctx.send_injected_request(target, method, param, payload)
                            if not r2:
                                continue
                            marker = self.ctx.context_detection_marker(payload, fallback=canary)
                            payload_hit = self.ctx.detect_active_context(r2.text, marker)
                            if (
                                self.ctx.context_payload_survived(r2.text, payload)
                                and payload_hit
                                and payload_hit.get("confidence") == "high"
                            ):
                                found.append(
                                    {
                                        "type": f"XSS (Reflected - {ptype})",
                                        "parameter": param,
                                        "payload": payload,
                                        "evidence": f"Context-aware payload reflected in {payload_hit.get('context', 'script context')}: {ptype}",
                                        "tool": "xsstrike_reflected_context",
                                        "confidence": "high",
                                        "status": "confirmed",
                                        "url": target["url"],
                                        "method": method,
                                    }
                                )
                                break
                        except Exception:
                            continue
                except Exception:
                    continue

        return found
