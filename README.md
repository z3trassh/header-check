# header-check

A small CLI that reads a page's response headers and reports missing or weak
security headers and cookie flags. It makes one GET request and changes nothing,
so it is safe to point at your own site or any site you are authorized to test.

## Run

```bash
python3 -m pip install -r requirements.txt
python3 -m header_check https://example.com
python3 -m header_check https://example.com --json
```

Exit code is `0` when nothing is flagged and `1` when there is at least one
finding, so it fits in CI against your own staging host.

## What it checks

| Check | Why |
| --- | --- |
| `Strict-Transport-Security` present, `max-age >= 15552000` | Forces HTTPS for return visits |
| `Content-Security-Policy` present, no `unsafe-inline` in `script-src` | First line against XSS |
| `X-Content-Type-Options: nosniff` | Stops MIME sniffing |
| `X-Frame-Options` or CSP `frame-ancestors` | Clickjacking |
| `Referrer-Policy` present | Limits referrer leakage |
| `Server` / `X-Powered-By` not verbose | Avoids version disclosure |
| `Set-Cookie` has `Secure`, `HttpOnly`, `SameSite` | Session-cookie hardening |

## Scope and limits

Header checks are a baseline, not an audit. A present header can still be
misconfigured, and a missing one is not always a vulnerability in context. Use
this to catch regressions, then review findings by hand. Only scan hosts you own
or are authorized to test.

## License

[MIT](LICENSE)
