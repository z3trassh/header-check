"""Pure header analysis. No network here, so the rules are easy to test."""

from __future__ import annotations

import re
from dataclasses import dataclass

MIN_HSTS_MAX_AGE = 15552000  # 180 days


@dataclass(frozen=True)
class Finding:
    header: str
    level: str  # "high" | "medium" | "low"
    detail: str


def _get(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _check_hsts(headers: dict[str, str]) -> Finding | None:
    value = _get(headers, "Strict-Transport-Security")
    if value is None:
        return Finding("Strict-Transport-Security", "high", "missing")
    match = re.search(r"max-age=(\d+)", value)
    if not match or int(match.group(1)) < MIN_HSTS_MAX_AGE:
        return Finding("Strict-Transport-Security", "medium", f"max-age below {MIN_HSTS_MAX_AGE}")
    return None


def _check_csp(headers: dict[str, str]) -> Finding | None:
    value = _get(headers, "Content-Security-Policy")
    if value is None:
        return Finding("Content-Security-Policy", "high", "missing")
    if "unsafe-inline" in value and "script-src" in value:
        return Finding("Content-Security-Policy", "medium", "script-src allows unsafe-inline")
    return None


def _check_frame(headers: dict[str, str]) -> Finding | None:
    csp = _get(headers, "Content-Security-Policy") or ""
    if _get(headers, "X-Frame-Options") is None and "frame-ancestors" not in csp:
        return Finding("X-Frame-Options", "medium", "no clickjacking protection")
    return None


def _check_cookies(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        name = value.split("=", 1)[0].strip()
        flags = value.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in flags]
        if missing:
            findings.append(Finding("Set-Cookie", "medium", f"{name} missing {', '.join(missing)}"))
    return findings


def audit_headers(headers: dict[str, str]) -> list[Finding]:
    """Return findings for one response's headers, most severe concerns first."""
    findings: list[Finding] = []
    for check in (_check_hsts, _check_csp, _check_frame):
        result = check(headers)
        if result is not None:
            findings.append(result)
    if _get(headers, "X-Content-Type-Options") != "nosniff":
        findings.append(Finding("X-Content-Type-Options", "low", "not 'nosniff'"))
    if _get(headers, "Referrer-Policy") is None:
        findings.append(Finding("Referrer-Policy", "low", "missing"))
    for header in ("Server", "X-Powered-By"):
        value = _get(headers, header)
        if value and any(char.isdigit() for char in value):
            findings.append(Finding(header, "low", f"version disclosure: {value}"))
    findings.extend(_check_cookies(headers))
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(findings, key=lambda f: order[f.level])
