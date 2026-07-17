from __future__ import annotations

import re

# Response body patterns indicating a CSRF/forgery check rejected the request.
CSRF_ERROR_PATTERNS = [
    r"invalid\s+csrf",
    r"csrf\s+token\s+(invalid|missing|mismatch|expired)",
    r"forbidden",
    r"403\s+forbidden",
    r"bad\s+request",
    r"token\s+mismatch",
    r"invalid\s+token",
    r"missing\s+token",
    r"csrf\s+verification\s+failed",
    r"request\s+forgery",
    r"unauthorized",
    r"security\s+token",
]
CSRF_ERROR_RE = re.compile("|".join(CSRF_ERROR_PATTERNS), re.IGNORECASE)


# Response body patterns indicating the state-changing action actually
# succeeded. Ported from Logic/vulnerability_scan/csrf/patterns.py with two
# fixes:
#   1. The original list included a bare r'success' pattern, which is a
#      literal substring of "unsuccessful" and "successfully" — meaning a
#      page that says "Update unsuccessful" would match this "success"
#      indicator and get reported as a working CSRF bypass. Removed rather
#      than word-boundary-patched, since \bsuccess\b still matches inside
#      "this was not a success" — the whole class of single-word signal is
#      unreliable without a baseline comparison, which `is_action_successful`
#      now does instead (see context.py).
#   2. Every remaining phrase pattern is wrapped with `_not_negated()`, a
#      negative lookbehind rejecting a "not"/"n't"/"never" directly before
#      it — otherwise "was not successfully changed" or "email was not
#      updated" still match the phrase as a plain substring. This isn't a
#      full negation parser (a negation word further back, e.g. "did not
#      manage to say it was successfully changed", still slips through),
#      but it closes the direct, common phrasing that a real rejected
#      request is likely to use.
def _not_negated(phrase: str) -> str:
    return rf"(?<!not\s)(?<!n't\s)(?<!never\s)\b{phrase}\b"


SUCCESS_PATTERNS = [
    r"\bemail\b(?:(?!\bnot\b|\bfail(?:ed)?\b|\berror\b|\binvalid\b).)*?\bupdated\b",
    _not_negated(r"successfully\s+changed"),
    _not_negated(r"has\s+been\s+updated"),
    _not_negated(r"profile\s+updated"),
    _not_negated(r"settings\s+saved"),
    _not_negated(r"password\s+changed"),
    _not_negated(r"account\s+updated"),
    r'"success":\s*true',
]
SUCCESS_RE = re.compile("|".join(SUCCESS_PATTERNS), re.IGNORECASE | re.DOTALL)

# Paths that are not state-changing and should not be flagged/tested as CSRF targets.
NON_STATE_CHANGING_PATHS = {
    "/login",
    "/signin",
    "/sign-in",
    "/log-in",
    "/search",
    "/logout",
    "/signout",
    "/sign-out",
    "/log-out",
    "/forgot-password",
    "/reset-password",
    "/register",
    "/signup",
    "/sign-up",
}
