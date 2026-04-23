#!/usr/bin/env python3
"""
Lab 06: Apache HTTP Server anomaly simulation baseline.

Generates RFC3164 syslog-wrapped Apache HTTP access events in a format that
IBM QRadar documents for the Apache HTTP Server DSM.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta, timezone

CLIENTS = [
    "10.10.20.24",
    "10.10.20.31",
    "10.10.21.18",
    "10.10.22.44",
    "10.10.23.15",
    "10.10.24.61",
]

SERVERS = [
    "172.16.210.237",
    "172.16.210.238",
    "172.16.220.10",
]

REQUESTS = [
    ("GET", "/", 200, 1432),
    ("GET", "/index.html", 200, 1543),
    ("GET", "/portal", 200, 2840),
    ("GET", "/reports/weekly", 200, 18320),
    ("GET", "/downloads/toolkit.zip", 200, 48320),
    ("GET", "/health", 200, 87),
    ("POST", "/login", 302, 512),
    ("HEAD", "/", 403, 123),
    ("GET", "/admin", 401, 211),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
]

REFERERS = [
    "-",
    "https://intranet.acme.local/home",
    "https://portal.office.com/",
    "https://github.com/",
]


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def apache_time(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def wrap_syslog(pri: int, ts: datetime, hostname: str, payload: str) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, message: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode("utf-8"), (host, port))
    sock.close()


def build_event(ts: datetime) -> str:
    src_ip = random.choice(CLIENTS)
    dst_ip = random.choice(SERVERS)
    method, uri, status, size = random.choice(REQUESTS)
    referer = random.choice(REFERERS)
    user_agent = random.choice(USER_AGENTS)
    return (
        f"httpd: {src_ip} {dst_ip} - - "
        f"[{apache_time(ts)}] "
        f'"{method} {uri} HTTP/1.1" '
        f"{status} {size} "
        f'"{referer}" '
        f'"{user_agent}"'
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Apache HTTP baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default="apache-http01.acme-lab.local", help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[INFO] Sending {args.count} Apache baseline events to {args.qradar_host}:{args.port}")
    print(f"[INFO] Hostname / Log Source Identifier: {args.hostname}")
    print()

    cursor = datetime.now(timezone.utc) - timedelta(minutes=5)
    for idx in range(1, args.count + 1):
        cursor += timedelta(seconds=random.randint(1, 6))
        payload = build_event(cursor)
        line = wrap_syslog(134, cursor, args.hostname, payload)
        print(f"[{idx:03d}] {line}")
        send_syslog(args.qradar_host, args.port, line)
        time.sleep(args.delay)

    print()
    print("[DONE] Baseline events sent.")


if __name__ == "__main__":
    main()
