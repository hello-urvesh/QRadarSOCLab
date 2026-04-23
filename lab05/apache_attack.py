#!/usr/bin/env python3
"""
Lab 06: Apache HTTP Server anomaly simulation attack generator.

Generates RFC3164 syslog-wrapped Apache HTTP access events in a format that
IBM QRadar documents for the Apache HTTP Server DSM.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta, timezone

SCENARIOS = {
    "all": "Run all suspicious web scenarios in sequence",
    "auth_burst": "Repeated login failures and redirects from one source",
    "admin_path_probe": "Enumeration of sensitive administrative paths",
    "scanner_wave": "Recon style requests to common discovery endpoints",
    "download_spike": "Burst of unusual downloads from one client",
    "redirect_chain": "Repeated POST to login followed by redirect flow",
}

ATTACKER_IPS = [
    "10.10.99.45",
    "10.10.99.77",
]

SERVERS = [
    "172.16.210.237",
    "172.16.210.238",
    "172.16.220.10",
]

USER_AGENTS = {
    "browser": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "scanner": [
        "curl/8.7.1",
        "python-requests/2.32.3",
        "sqlmap/1.8.4",
        "Nmap Scripting Engine",
    ],
}

REFERER = "-"


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


def build_event(ts: datetime, src_ip: str, dst_ip: str, method: str, uri: str, status: int, size: int, user_agent: str) -> str:
    return (
        f"httpd: {src_ip} {dst_ip} - - "
        f"[{apache_time(ts)}] "
        f'"{method} {uri} HTTP/1.1" '
        f"{status} {size} "
        f'"{REFERER}" '
        f'"{user_agent}"'
    )


def auth_burst(ts: datetime):
    events = []
    src_ip = ATTACKER_IPS[0]
    dst_ip = random.choice(SERVERS)
    for _ in range(40):
        status = random.choice([401, 403, 302])
        size = 210 if status in (401, 403) else 512
        events.append((src_ip, dst_ip, "POST", "/login", status, size, random.choice(USER_AGENTS["browser"])))
    return events


def admin_path_probe(ts: datetime):
    events = []
    src_ip = ATTACKER_IPS[0]
    dst_ip = random.choice(SERVERS)
    paths = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/console",
        "/server-status",
        "/phpmyadmin",
        "/actuator/health",
        "/debug",
    ]
    for path in paths * 4:
        events.append((src_ip, dst_ip, "GET", path, random.choice([401, 403, 404]), random.randint(120, 420), random.choice(USER_AGENTS["scanner"])))
    return events


def scanner_wave(ts: datetime):
    events = []
    dst_ip = random.choice(SERVERS)
    paths = [
        "/.git/config",
        "/.env",
        "/robots.txt",
        "/sitemap.xml",
        "/api/v1/users",
        "/backup.zip",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    ]
    for attacker in ATTACKER_IPS:
        for path in paths * 2:
            events.append((attacker, dst_ip, "GET", path, random.choice([200, 403, 404]), random.randint(90, 600), random.choice(USER_AGENTS["scanner"])))
    return events


def download_spike(ts: datetime):
    events = []
    src_ip = ATTACKER_IPS[1]
    dst_ip = random.choice(SERVERS)
    downloads = [
        "/downloads/admin-toolkit.zip",
        "/downloads/db_backup.sql.gz",
        "/downloads/hr-export.csv",
        "/downloads/finance-q2.xlsx",
    ]
    for item in downloads * 6:
        events.append((src_ip, dst_ip, "GET", item, 200, random.randint(25000, 950000), random.choice(USER_AGENTS["browser"])))
    return events


def redirect_chain(ts: datetime):
    events = []
    src_ip = ATTACKER_IPS[0]
    dst_ip = random.choice(SERVERS)
    for _ in range(20):
        events.append((src_ip, dst_ip, "POST", "/login", 302, 512, random.choice(USER_AGENTS["browser"])))
        events.append((src_ip, dst_ip, "GET", "/portal", 200, 2400, random.choice(USER_AGENTS["browser"])))
    return events


SCENARIO_BUILDERS = {
    "auth_burst": auth_burst,
    "admin_path_probe": admin_path_probe,
    "scanner_wave": scanner_wave,
    "download_spike": download_spike,
    "redirect_chain": redirect_chain,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Apache HTTP attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default="apache-http01.acme-lab.local", help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[INFO] Sending Apache attack events to {args.qradar_host}:{args.port}")
    print(f"[INFO] Hostname / Log Source Identifier: {args.hostname}")
    print(f"[INFO] Scenario: {args.scenario}")
    print()

    cursor = datetime.now(timezone.utc) - timedelta(minutes=2)
    scenario_names = [name for name in SCENARIO_BUILDERS] if args.scenario == "all" else [args.scenario]
    seq = 0
    for scenario_name in scenario_names:
        print(f"[INFO] Emitting scenario: {scenario_name}")
        for src_ip, dst_ip, method, uri, status, size, ua in SCENARIO_BUILDERS[scenario_name](cursor):
            cursor += timedelta(seconds=random.uniform(0.2, 2.0))
            payload = build_event(cursor, src_ip, dst_ip, method, uri, status, size, ua)
            line = wrap_syslog(134, cursor, args.hostname, payload)
            seq += 1
            print(f"[{seq:03d}] {line}")
            send_syslog(args.qradar_host, args.port, line)
            time.sleep(args.delay)

    print()
    print("[DONE] Attack events sent.")


if __name__ == "__main__":
    main()
