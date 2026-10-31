"""CLI: fetch one URL and print its header findings."""

from __future__ import annotations

import argparse
import json
import sys

import requests

from header_check.checks import audit_headers

MARK = {"high": "[!]", "medium": "[-]", "low": "[.]"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="header-check", description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    try:
        response = requests.get(args.url, timeout=args.timeout, allow_redirects=True)
    except requests.RequestException as error:
        print(f"request failed: {error}", file=sys.stderr)
        return 2

    findings = audit_headers(dict(response.headers))

    if args.json:
        print(json.dumps([finding.__dict__ for finding in findings], indent=2))
    elif not findings:
        print(f"{args.url}: no findings")
    else:
        print(f"{args.url}: {len(findings)} finding(s)")
        for finding in findings:
            print(f"  {MARK[finding.level]} {finding.header}: {finding.detail}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
