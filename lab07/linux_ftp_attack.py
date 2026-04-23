#!/usr/bin/env python3
"""
Linux OS FTP attack simulator for QRadar.

Important:
IBM confirms Linux OS supports FTP events, but IBM's public sample page does not
publish an FTP sample payload. This script uses a conservative vsftpd-style syslog
shape as the best current candidate for FTP abuse simulation.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta, timezone

HOSTNAME = "linux-ftp01.acme-lab.local"

SCENARIOS = {
    "all": "Run all suspicious FTP scenarios",
    "ftp_failure_burst": "Repeated failed FTP logins from one source",
    "service_account_ftp_login": "Service account logging into FTP interactively",
    "multi_source_same_user": "Same username used from multiple remote IPs",
    "abnormal_download_spike": "Repeated large downloads from one source",
}

ATTACKER_IPS = [
    "185.220.101.14",
    "91.243.85.44",
    "103.244.120.7",
    "45.142.214.33",
]

NORMAL_USERS = [
    "alice",
    "bob",
    "carol",
]

SERVICE_USERS = [
    "svc_backup",
    "svc_batch",
    "svc_sync",
]

SENSITIVE_FILES = [
    "/pub/backups/db_backup_2026_04_25.sql.gz",
    "/pub/finance/payroll-q2.xlsx",
    "/pub/hr/employee-export.csv",
    "/pub/secrets/deploy-archive.tgz",
]

PRIORITY_INFO = 86
PRIORITY_WARN = 38


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, msg: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode("utf-8"), (host, port))
    sock.close()


def connect_line(ip: str) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    return PRIORITY_INFO, f'vsftpd[{pid}]: CONNECT: Client "{ip}"'


def fail_login_line(user: str, ip: str) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    return PRIORITY_WARN, f'vsftpd[{pid}]: [{user}] FAIL LOGIN: Client "{ip}"'


def ok_login_line(user: str, ip: str) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    return PRIORITY_INFO, f'vsftpd[{pid}]: [{user}] OK LOGIN: Client "{ip}"'


def download_line(user: str, ip: str, filename: str, size: int) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    return (
        PRIORITY_INFO,
        f'vsftpd[{pid}]: [{user}] OK DOWNLOAD: Client "{ip}", "{filename}", {size} bytes, {random.randint(100, 900)}.00Kbyte/sec'
    )


def emit_ftp_failure_burst():
    ip = ATTACKER_IPS[0]
    user = random.choice(NORMAL_USERS)
    for _ in range(15):
        yield connect_line(ip)
        yield fail_login_line(user, ip)


def emit_service_account_ftp_login():
    ip = ATTACKER_IPS[1]
    user = random.choice(SERVICE_USERS)
    for _ in range(20):
        yield connect_line(ip)
        yield ok_login_line(user, ip)


def emit_multi_source_same_user():
    user = random.choice(SERVICE_USERS + NORMAL_USERS)
    for ip in ATTACKER_IPS:
        for _ in range(8):
            yield connect_line(ip)
            yield ok_login_line(user, ip)


def emit_abnormal_download_spike():
    ip = ATTACKER_IPS[2]
    user = random.choice(NORMAL_USERS + SERVICE_USERS)
    for _ in range(5):
        yield connect_line(ip)
        yield ok_login_line(user, ip)
    for _ in range(25):
        yield download_line(
            user=user,
            ip=ip,
            filename=random.choice(SENSITIVE_FILES),
            size=random.randint(250000, 8500000),
        )


def emit_for_scenario(name: str):
    if name == "ftp_failure_burst":
        yield from emit_ftp_failure_burst()
    elif name == "service_account_ftp_login":
        yield from emit_service_account_ftp_login()
    elif name == "multi_source_same_user":
        yield from emit_multi_source_same_user()
    elif name == "abnormal_download_spike":
        yield from emit_abnormal_download_spike()
    elif name == "all":
        for scenario in [
            "ftp_failure_burst",
            "service_account_ftp_login",
            "multi_source_same_user",
            "abnormal_download_spike",
        ]:
            yield from emit_for_scenario(scenario)


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux OS FTP attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending Linux OS FTP attack events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print(f"[*] Scenario: {args.scenario}")
    print()

    ts = datetime.now(timezone.utc) - timedelta(minutes=2)
    seq = 0

    for pri, payload in emit_for_scenario(args.scenario):
        ts += timedelta(seconds=random.uniform(0.2, 1.5))
        seq += 1
        msg = wrap_syslog(ts, args.hostname, payload, pri)
        print(f"[{seq:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Attack events sent.")


if __name__ == "__main__":
    main()
