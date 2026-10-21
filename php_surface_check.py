#!/usr/bin/env python3
"""Read-only HTTP inventory of visible PHP hints. This does not test PHP2Shell."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_TARGETS = 250
PHP_WORD = re.compile(r"\bphp\b", re.IGNORECASE)
PHP_VERSION = re.compile(
    r"\bPHP(?:\s*(?:/|version)?\s*)(\d+\.\d+(?:\.\d+)?)\b",
    re.IGNORECASE,
)


class NoRedirectHandler(HTTPRedirectHandler):
    """Keep each request on the exact allowlisted URL supplied by the user."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_target(raw: str, line_no: int, allow_private: bool) -> str:
    value = raw.strip()
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"line {line_no}: control characters are not allowed")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port  # Validate malformed and out-of-range ports.
    except ValueError as exc:
        raise ValueError(f"line {line_no}: invalid URL ({exc})") from exc

    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc or not hostname:
        raise ValueError(f"line {line_no}: provide a full http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"line {line_no}: URLs containing credentials are rejected")
    if parsed.query or parsed.fragment:
        raise ValueError(f"line {line_no}: query strings and fragments are rejected")
    if "*" in parsed.netloc:
        raise ValueError(f"line {line_no}: wildcard targets are rejected; list exact URLs")
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        if not allow_private:
            raise ValueError(f"line {line_no}: localhost requires --allow-private")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global and not allow_private:
        raise ValueError(f"line {line_no}: non-public IP targets require --allow-private")

    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", ""))


def load_targets(target_file: Path, allow_private: bool) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    try:
        lines = target_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"could not read target file: {exc}") from exc

    for line_no, raw in enumerate(lines, start=1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        target = normalize_target(value, line_no, allow_private)
        if target not in seen:
            seen.add(target)
            targets.append(target)
        if len(targets) > MAX_TARGETS:
            raise ValueError(f"target file exceeds the {MAX_TARGETS}-URL limit")
    if not targets:
        raise ValueError("target file contains no URLs")
    return targets


def version_from_header(headers, name: str) -> str | None:
    match = PHP_VERSION.search(headers.get(name, "") or "")
    return match.group(1) if match else None


def inspect_target(opener, target: str, timeout: float) -> dict:
    request = Request(
        target,
        method="HEAD",
        headers={
            "Accept": "*/*",
            "Connection": "close",
            "User-Agent": "PHP-Surface-Inventory/1.0 (read-only HEAD request)",
        },
    )
    status = None
    headers = None
    error = None
    try:
        response = opener.open(request, timeout=timeout)
        try:
            status, headers = response.status, response.headers
        finally:
            response.close()
    except HTTPError as exc:
        status, headers = exc.code, exc.headers
        exc.close()
    except (URLError, socket.timeout, TimeoutError, OSError) as exc:
        error = type(exc).__name__

    path_hint = urlsplit(target).path.lower().endswith(".php")
    if headers is None:
        return {
            "target": target,
            "request": "HEAD",
            "http_status": status,
            "request_error": error or "NoResponse",
            "php_signal": "unknown",
            "reported_php_version": None,
            "version_header": None,
            "signals": {
                "x_powered_by_mentions_php": False,
                "server_header_mentions_php": False,
                "php_session_cookie_name_seen": False,
                "requested_path_ends_with_php": path_hint,
            },
            "patch_status": "unknown",
        }

    powered_by = headers.get("X-Powered-By", "") or ""
    server = headers.get("Server", "") or ""
    cookie_names = set()
    for set_cookie in headers.get_all("Set-Cookie", []):
        name, separator, _value = set_cookie.split(";", 1)[0].partition("=")
        if separator:
            cookie_names.add(name.strip().casefold())

    version = version_from_header(headers, "X-Powered-By")
    version_header = "X-Powered-By" if version else None
    if version is None:
        version = version_from_header(headers, "Server")
        version_header = "Server" if version else None

    signals = {
        "x_powered_by_mentions_php": bool(PHP_WORD.search(powered_by)),
        "server_header_mentions_php": bool(PHP_WORD.search(server)),
        "php_session_cookie_name_seen": "phpsessid" in cookie_names,
        "requested_path_ends_with_php": path_hint,
    }
    return {
        "target": target,
        "request": "HEAD",
        "http_status": status,
        "request_error": None,
        "php_signal": "php_indicated" if any(signals.values()) or version else "no_php_signal_in_response",
        "reported_php_version": version,
        "version_header": version_header,
        "signals": signals,
        "patch_status": "unknown",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Make one read-only HEAD request to each exact URL in an approved target file."
    )
    parser.add_argument("--targets", required=True, type=Path, help="UTF-8 file with one exact URL per line")
    parser.add_argument("--output", type=Path, help="write JSON report to a new file; otherwise print it")
    parser.add_argument("--timeout", type=float, default=6.0, help="per-request timeout in seconds (1-30; default: 6)")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="allow localhost and private IP literals when they are explicitly in scope",
    )
    args = parser.parse_args()

    if not 1.0 <= args.timeout <= 30.0:
        parser.error("--timeout must be between 1 and 30 seconds")
    if args.output and args.output.exists():
        parser.error(f"refusing to overwrite existing output file: {args.output}")
    if args.output:
        try:
            if args.output.resolve() == args.targets.resolve():
                parser.error("--output must not be the target file")
        except OSError:
            pass
    try:
        targets = load_targets(args.targets, args.allow_private)
    except ValueError as exc:
        parser.error(str(exc))

    opener = build_opener(NoRedirectHandler())
    results = [inspect_target(opener, target, args.timeout) for target in targets]
    report = {
        "tool": "PHP Surface Inventory",
        "tool_version": "1.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "request_policy": {
            "method": "HEAD",
            "requests_per_url": 1,
            "follows_redirects": False,
            "sends_request_body": False,
            "sends_cookies_or_authentication": False,
            "reads_response_body": False,
            "stores_cookie_values": False,
        },
        "interpretation": (
            "HTTP hints do not prove the backend PHP build or vulnerability status. "
            "No visible PHP hint does not establish that PHP is absent. Verify patch status "
            "with the runtime owner and compare against the current official PHP advisory."
        ),
        "results": results,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        try:
            with args.output.open("x", encoding="utf-8") as output_file:
                output_file.write(rendered)
        except OSError as exc:
            print(f"could not write report: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote {len(results)} results to {args.output}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
