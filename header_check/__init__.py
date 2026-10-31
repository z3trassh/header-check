"""header-check: report missing or weak HTTP security headers and cookie flags."""

from header_check.checks import Finding, audit_headers

__all__ = ["Finding", "audit_headers"]
