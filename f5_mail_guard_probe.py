#!/usr/bin/env python3
"""
f5_mail_guard_probe.py

Authorized, controlled validation of rate limiting / anti-automation controls
for an email-triggering HTTP API behind F5.

It intentionally does NOT implement WAF evasion, source-IP spoofing, header
spoofing, or other techniques intended to defeat F5 controls.

Examples:
  python3 f5_mail_guard_probe.py -r request.txt --count 20 --delay 5
  python3 f5_mail_guard_probe.py -r request.txt --count 20 --delay-sequence 5,7,3,9,11
  python3 f5_mail_guard_probe.py -r request.txt --count 20 --random-delay 3,11
  python3 f5_mail_guard_probe.py -r request.txt --count 20 --delay 5 --fresh-request-id
"""

import argparse
import csv
import json
import random
import sys
import time
import uuid
from collections import Counter
from http.client import HTTPSConnection, HTTPConnection
from pathlib import Path

RATE_HEADERS = {
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
    "ratelimit-reset", "server", "via", "x-cache"
}

def parse_raw_request(path):
    raw = Path(path).read_bytes()
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, body = raw.partition(b"\n\n")
    lines = head.decode("iso-8859-1").replace("\r\n", "\n").split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("Invalid HTTP request line")
    method, target = parts[:2]
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    hdict = {k.lower(): v for k, v in headers}
    if "host" not in hdict:
        raise ValueError("No Host header in raw request")
    return method, target, headers, body, hdict["host"]

def replace_header(headers, name, value):
    out, done = [], False
    for k, v in headers:
        if k.lower() == name.lower():
            out.append((k, value))
            done = True
        else:
            out.append((k, v))
    if not done:
        out.append((name, value))
    return out

def parse_pair(s):
    vals = [float(x.strip()) for x in s.split(",")]
    if len(vals) != 2 or vals[0] < 0 or vals[1] < vals[0]:
        raise argparse.ArgumentTypeError("Expected MIN,MAX with 0 <= MIN <= MAX")
    return vals

def parse_sequence(s):
    vals = [float(x.strip()) for x in s.split(",") if x.strip()]
    if not vals or any(x < 0 for x in vals):
        raise argparse.ArgumentTypeError("Expected comma-separated non-negative delays")
    return vals

def main():
    p = argparse.ArgumentParser(
        description="Controlled F5/API email rate-limit validation from a Burp raw request."
    )
    p.add_argument("-r", "--request", required=True, help="Burp raw HTTP request file")
    p.add_argument("-n", "--count", type=int, default=10, help="Request count (default 10)")
    p.add_argument("--delay", type=float, default=5.0, help="Fixed inter-request delay")
    p.add_argument("--delay-sequence", type=parse_sequence,
                   help="Cycle through delays, e.g. 5,7,3,9,11")
    p.add_argument("--random-delay", type=parse_pair, metavar="MIN,MAX",
                   help="Random delay for each interval, e.g. 3,11")
    p.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPS")
    p.add_argument("--timeout", type=float, default=20)
    p.add_argument("--fresh-request-id", action="store_true",
                   help="Generate a fresh X-Request-ID each request")
    p.add_argument("--stop-on-block", action="store_true",
                   help="Stop on 403, 406, or 429")
    p.add_argument("--stop-on-429", action="store_true", help="Stop specifically on 429")
    p.add_argument("--stop-after-success", type=int,
                   help="Stop after N HTTP 2xx responses (safety guard)")
    p.add_argument("--max-runtime", type=float,
                   help="Stop after this many seconds")
    p.add_argument("--max-count", type=int, default=100,
                   help="Local safety ceiling; default 100")
    p.add_argument("--csv", default="f5_probe_results.csv", help="CSV output path")
    p.add_argument("--body-preview", type=int, default=180,
                   help="Response body preview bytes")
    args = p.parse_args()

    if args.count < 1:
        sys.exit("--count must be >= 1")
    if args.count > args.max_count:
        sys.exit(f"Requested {args.count}, but --max-count is {args.max_count}.")
    if args.delay < 0:
        sys.exit("--delay must be >= 0")

    method, target, headers, body, host = parse_raw_request(args.request)
    use_https = not args.http
    port = 443 if use_https else 80
    hostname = host
    if ":" in host and not host.startswith("["):
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            hostname, port = maybe_host, int(maybe_port)

    # Transport headers are recalculated.
    drop = {"content-length", "connection", "proxy-connection"}
    base_headers = [(k, v) for k, v in headers if k.lower() not in drop]

    print(f"Target: {method} {'https' if use_https else 'http'}://{host}{target}")
    print(f"Count: {args.count}; safety ceiling: {args.max_count}")
    if args.delay_sequence:
        print("Delay sequence:", args.delay_sequence)
    elif args.random_delay:
        print(f"Random delay: {args.random_delay[0]}..{args.random_delay[1]} sec")
    else:
        print(f"Fixed delay: {args.delay} sec")
    print(f"CSV: {args.csv}")
    print("-" * 90)

    start_all = time.monotonic()
    results, successes = [], 0

    with open(args.csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "request_no", "timestamp", "status", "elapsed_sec", "response_bytes",
            "planned_next_delay", "rate_headers", "body_preview", "error"
        ])
        writer.writeheader()

        for i in range(1, args.count + 1):
            if args.max_runtime and time.monotonic() - start_all >= args.max_runtime:
                print("Stopping: --max-runtime reached.")
                break

            hs = list(base_headers)
            if args.fresh_request_id:
                hs = replace_header(hs, "X-Request-ID", str(uuid.uuid4()))
            hdrs = {k: v for k, v in hs}
            hdrs["Content-Length"] = str(len(body))

            if args.delay_sequence:
                next_delay = args.delay_sequence[(i - 1) % len(args.delay_sequence)]
            elif args.random_delay:
                next_delay = random.uniform(*args.random_delay)
            else:
                next_delay = args.delay

            begun = time.time()
            row = {
                "request_no": i, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "", "elapsed_sec": "", "response_bytes": "",
                "planned_next_delay": round(next_delay, 3),
                "rate_headers": "", "body_preview": "", "error": ""
            }

            try:
                Conn = HTTPSConnection if use_https else HTTPConnection
                conn = Conn(hostname, port, timeout=args.timeout)
                conn.request(method, target, body=body, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read()
                elapsed = time.time() - begun

                interesting = {
                    k: v for k, v in resp.getheaders() if k.lower() in RATE_HEADERS
                }
                preview = data[:args.body_preview].decode("utf-8", "replace").replace("\n", " ")

                row.update({
                    "status": resp.status,
                    "elapsed_sec": round(elapsed, 4),
                    "response_bytes": len(data),
                    "rate_headers": json.dumps(interesting, ensure_ascii=False),
                    "body_preview": preview
                })
                writer.writerow(row)
                fh.flush()
                results.append(resp.status)

                if 200 <= resp.status < 300:
                    successes += 1

                print(
                    f"[{i:03}] HTTP {resp.status} | {elapsed:.3f}s | "
                    f"{len(data)} bytes | next={next_delay:.2f}s | {interesting} | {preview!r}"
                )
                conn.close()

                if args.stop_on_429 and resp.status == 429:
                    print("Stopping: HTTP 429 observed.")
                    break
                if args.stop_on_block and resp.status in {403, 406, 429}:
                    print(f"Stopping: possible enforcement response HTTP {resp.status}.")
                    break
                if args.stop_after_success and successes >= args.stop_after_success:
                    print("Stopping: --stop-after-success reached.")
                    break

            except Exception as e:
                row["elapsed_sec"] = round(time.time() - begun, 4)
                row["error"] = str(e)
                writer.writerow(row)
                fh.flush()
                results.append("ERROR")
                print(f"[{i:03}] ERROR: {e}")

            if i < args.count:
                time.sleep(next_delay)

    print("-" * 90)
    print("Status summary:", dict(Counter(map(str, results))))
    print("HTTP 2xx responses:", successes)
    print(f"Results written to {args.csv}")
    print("\nUse F5/application/mail logs to determine whether accepted HTTP requests")
    print("actually generated messages and which security control handled each request.")

if __name__ == "__main__":
    main()
