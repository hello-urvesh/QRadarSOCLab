#!/usr/bin/env python3
"""
Linux OS FTP baseline simulator for QRadar.

Important:
IBM confirms the Linux OS DSM supports FTP events over syslog/syslog-ng, but IBM's
public Linux OS sample page does not publish an FTP sample payload the way it does
for SSH/PAM. This script therefore uses a conservative vsftpd-style syslog shape
as the best current candidate for Linux OS FTP simulation.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta, timezone

HOSTNAME = "linux-ftp01.acme-lab.local"

USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "ftpuser1",
]

CLIENT_IPS = [
    "10.20.30.11",
    "10.20.30.12",
    "10.20.30.13",
    "10.20.30.14",
]

FILES = [
    "/pub/releases/client-v1.2.4.tar.gz",
    "/pub/docs/runbook.pdf",
    "/pub/exports/inventory.csv",
    "/pub/patches/agent-update.bin",
]

PRIORITY_INFO = 86


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, msg: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode("utf-8"), (host, port))
    sock.close()


def build_connect() -> str:
    pid = random.randint(1000, 50000)
    ip = random.choice(CLIENT_IPS)
    return f'vsftpd[{pid}]: CONNECT: Client "{ip}"'


def build_ok_login() -> str:
    pid = random.randint(1000, 50000)
    ip = random.choice(CLIENT_IPS)
    user = random.choice(USERS)
    return f'vsftpd[{pid}]: [{user}] OK LOGIN: Client "{ip}"'


def build_transfer() -> str:
    pid = random.randint(1000, 50000)
    ip = random.choice(CLIENT_IPS)
    user = random.choice(USERS)
    filename = random.choice(FILES)
    return f'vsftpd[{pid}]: [{user}] OK DOWNLOAD: Client "{ip}", "{filename}", {random.randint(1024, 250000)} bytes, {random.randint(20, 500)}.00Kbyte/sec'


def build_event() -> str:
    return random.choices(
        population=[build_connect, build_ok_login, build_transfer],
        weights=[30, 45, 25],
        k=1,
    )[0]()


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux OS FTP baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending {args.count} Linux OS FTP baseline events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print()

    ts = datetime.now(timezone.utc) - timedelta(minutes=5)

    for i in range(1, args.count + 1):
        ts += timedelta(seconds=random.randint(1, 6))
        payload = build_event()
        msg = wrap_syslog(ts, args.hostname, payload, PRIORITY_INFO)
        print(f"[{i:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Baseline events sent.")


if __name__ == "__main__":
    main()
