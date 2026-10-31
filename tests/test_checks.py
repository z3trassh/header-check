from header_check.checks import audit_headers

SECURE = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax",
}


def headers(**overrides):
    merged = dict(SECURE)
    merged.update(overrides)
    return merged


def test_secure_headers_have_no_findings():
    assert audit_headers(SECURE) == []


def test_missing_hsts_is_high():
    findings = audit_headers({k: v for k, v in SECURE.items() if k != "Strict-Transport-Security"})
    assert findings[0].header == "Strict-Transport-Security"
    assert findings[0].level == "high"


def test_short_hsts_is_medium():
    findings = audit_headers(headers(**{"Strict-Transport-Security": "max-age=600"}))
    assert any(f.header == "Strict-Transport-Security" and f.level == "medium" for f in findings)


def test_cookie_without_flags_is_flagged():
    findings = audit_headers(headers(**{"Set-Cookie": "sid=abc"}))
    cookie = next(f for f in findings if f.header == "Set-Cookie")
    assert "secure" in cookie.detail and "httponly" in cookie.detail and "samesite" in cookie.detail


def test_version_disclosure_is_flagged():
    findings = audit_headers(headers(**{"Server": "nginx/1.25.3"}))
    assert any(f.header == "Server" for f in findings)


def test_findings_are_sorted_by_severity():
    findings = audit_headers({"Set-Cookie": "sid=abc"})
    levels = [f.level for f in findings]
    assert levels == sorted(levels, key={"high": 0, "medium": 1, "low": 2}.get)
