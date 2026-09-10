#!/usr/bin/env python3
"""
waf_mail_probe.py
Authorized API/WAF rate-limit test helper.

Reads a Burp "Copy to file"/saved raw HTTP request (-r), replays it at a
controlled rate, and records whether responses remain successful or begin
getting blocked/throttled.

Example:
  python3 waf_mail_probe.py -r request.txt --https -n 20 --delay 5
  python3 waf_mail_probe.py -r request.txt --https -n 50 --delay 2 --jitter 0.5
"""

import argparse
import json
import random
import re
import ssl
import sys
import time
import uuid
from collections import Counter
from http.client import HTTPSConnection, HTTPConnection
from urllib.parse import urlsplit

def parse_raw_request(path):
    raw = Path(path).read_bytes()
    # Burp files normally use CRLF, but tolerate LF.
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.decode("iso-8859-1").replace("\r\n", "\n").split("\n")
    if not lines or len(lines[0].split()) < 2:
        raise ValueError("Could not parse HTTP request line")

    method, target, *_ = lines[0].split()
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))

    hdict = {k.lower(): v for k, v in headers}
    host = hdict.get("host")
    if not host:
        raise ValueError("Raw request has no Host header")
    return method, target, headers, body, host

def replace_header(headers, name, value):
    out = []
    replaced = False
    for k, v in headers:
        if k.lower() == name.lower():
            out.append((k, value))
            replaced = True
        else:
            out.append((k, v))
    if not replaced:
        out.append((name, value))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", "--request", required=True, help="Burp raw request file")
    ap.add_argument("-n", "--count", type=int, default=10,
                    help="Number of requests (default 10)")
    ap.add_argument("--delay", type=float, default=5.0,
                    help="Seconds between requests (default 5)")
    ap.add_argument("--jitter", type=float, default=0.0,
                    help="+/- random delay jitter in seconds")
    ap.add_argument("--https", action="store_true", default=True,
                    help="Use HTTPS (default)")
    ap.add_argument("--http", action="store_true", help="Use HTTP instead")
    ap.add_argument("--timeout", type=float, default=20)
    ap.add_argument("--fresh-request-id", action="store_true",
                    help="Generate a fresh X-Request-ID each request")
    ap.add_argument("--stop-on-429", action="store_true",
                    help="Stop when HTTP 429 is observed")
    ap.add_argument("--max-count", type=int, default=100,
                    help="Hard safety cap (default 100)")
    args = ap.parse_args()

    if args.count < 1 or args.count > args.max_count:
        sys.exit(f"count must be 1..{args.max_count}")
    if args.delay < 0:
        sys.exit("delay must be >= 0")

    method, target, headers, body, host = parse_raw_request(args.request)
    use_https = not args.http
    port = 443 if use_https else 80

    # Handle Host:port
    hostname = host
    if host.startswith("["):
        pass
    elif ":" in host:
        hostname, p = host.rsplit(":", 1)
        if p.isdigit():
            port = int(p)

    # Avoid forwarding stale transport-calculated headers.
    drop = {"content-length", "connection", "proxy-connection"}
    base_headers = [(k, v) for k, v in headers if k.lower() not in drop]

    print(f"Target: {method} {'https' if use_https else 'http'}://{host}{target}")
    print(f"Requests: {args.count}, delay: {args.delay}s, jitter: ±{args.jitter}s")
    print("JWT/body are taken unchanged from the Burp request file.")
    print("-" * 78)

    results = []
    for i in range(1, args.count + 1):
        hs = list(base_headers)
        if args.fresh_request_id:
            hs = replace_header(hs, "X-Request-ID", str(uuid.uuid4()))

        hdr_dict = {k: v for k, v in hs}
        hdr_dict["Content-Length"] = str(len(body))
        started = time.time()

        try:
            Conn = HTTPSConnection if use_https else HTTPConnection
            conn = Conn(hostname, port, timeout=args.timeout)
            conn.request(method, target, body=body, headers=hdr_dict)
            resp = conn.getresponse()
            data = resp.read()
            elapsed = time.time() - started

            # Useful rate-limit/WAF indicators without trying to evade controls.
            interesting = {}
            for k, v in resp.getheaders():
                if k.lower() in {
                    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-ratelimit-reset", "server", "via", "x-cache"
                }:
                    interesting[k] = v

            preview = data[:180].decode("utf-8", "replace").replace("\n", " ")
            print(f"[{i:03}] HTTP {resp.status}  {elapsed:.3f}s  "
                  f"bytes={len(data)}  headers={interesting}  body={preview!r}")
            results.append((resp.status, elapsed))

            conn.close()
            if args.stop_on_429 and resp.status == 429:
                print("Stopping: HTTP 429 observed.")
                break

        except Exception as e:
            elapsed = time.time() - started
            print(f"[{i:03}] ERROR after {elapsed:.3f}s: {e}")
            results.append(("ERROR", elapsed))

        if i < args.count:
            wait = max(0, args.delay + random.uniform(-args.jitter, args.jitter))
            time.sleep(wait)

    counts = Counter(str(x[0]) for x in results)
    print("-" * 78)
    print("Status summary:", dict(counts))
    if results:
        avg = sum(x[1] for x in results) / len(results)
        print(f"Average response time: {avg:.3f}s")
    print("\nInterpretation:")
    print("  429       -> rate limiting/throttling is clearly being enforced")
    print("  403/406   -> may indicate WAF/policy blocking; verify against WAF logs")
    print("  repeated 2xx -> request was accepted at this test rate; confirm actual")
    print("                  email generation and correlate with WAF/app logs")
    print("  5xx/timeouts -> investigate upstream/WAF/app behavior; don't assume block")

if __name__ == "__main__":
    main()
