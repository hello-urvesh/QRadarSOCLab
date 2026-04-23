#!/usr/bin/env python3
"""
Linux OS baseline simulator for QRadar.

Use case:
Normal Linux SSH and PAM activity with occasional expected service account noise,
but no clearly suspicious service account interactive login pattern.

Format rationale:
Built around IBM QRadar Linux OS sample message patterns for sshd/PAM so QRadar
can normalize Event ID, Source IP, Source Port, and Username correctly.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta, timezone

HOSTNAME = "linux-auth01.acme-lab.local"

NORMAL_USERS = [
    "alice",
    "bob",
    "carol",
    "dave",
    "erin",
    "opsadmin",
]

SERVICE_ACCOUNTS = [
    "svc_backup",
    "svc_monitor",
    "svc_deploy",
]

TRUSTED_IPS = [
    "10.20.30.11",
    "10.20.30.12",
    "10.20.30.13",
    "10.20.30.14",
]

MGMT_IPS = [
    "10.20.40.5",
    "10.20.40.8",
]

PRIORITY_FAILED = 38
PRIORITY_INFO = 86
PRIORITY_PAM = 118


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, msg: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode("utf-8"), (host, port))
    sock.close()


def build_failed_password(ts: datetime) -> tuple[int, str]:
    user = random.choice(NORMAL_USERS)
    src_ip = random.choice(TRUSTED_IPS)
    src_port = random.randint(40000, 65000)
    pid = random.randint(1000, 50000)
    payload = (
        f"sshd[{pid}]: Failed password for {user} from {src_ip} "
        f"port {src_port} ssh2"
    )
    return PRIORITY_FAILED, payload


def build_invalid_user_failed(ts: datetime) -> tuple[int, str]:
    user = random.choice(["test", "admin1", "oracle", "backup", "scanner"])
    src_ip = random.choice(TRUSTED_IPS)
    src_port = random.randint(40000, 65000)
    pid = random.randint(1000, 50000)
    payload = (
        f"sshd[{pid}]: Failed password for invalid user {user} from {src_ip} "
        f"port {src_port} ssh2"
    )
    return PRIORITY_FAILED, payload


def build_accept_password(ts: datetime) -> tuple[int, str]:
    user = random.choice(NORMAL_USERS)
    src_ip = random.choice(TRUSTED_IPS)
    src_port = random.randint(40000, 65000)
    pid = random.randint(1000, 50000)
    payload = (
        f"sshd[{pid}]: Accepted password for {user} from {src_ip} "
        f"port {src_port} ssh2"
    )
    return PRIORITY_INFO, payload


def build_pam_open_session(ts: datetime) -> tuple[int, str]:
    user = random.choice(NORMAL_USERS)
    pid = random.randint(1000, 50000)
    payload = (
        f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} "
        f"by (uid=0)"
    )
    return PRIORITY_INFO, payload


def build_expected_service_noise(ts: datetime) -> tuple[int, str]:
    """
    Keep a small amount of service-account-related activity so the attack stands out.
    This is intentionally rare and from expected management IPs.
    """
    user = random.choice(SERVICE_ACCOUNTS)
    src_ip = random.choice(MGMT_IPS)
    src_port = random.randint(40000, 65000)
    pid = random.randint(1000, 50000)
    payload = (
        f"sshd[{pid}]: Failed password for {user} from {src_ip} "
        f"port {src_port} ssh2"
    )
    return PRIORITY_FAILED, payload


def build_event(ts: datetime) -> tuple[int, str]:
    choice = random.choices(
        population=["accept", "pam", "failed", "invalid", "svc_noise"],
        weights=[45, 25, 18, 8, 4],
        k=1,
    )[0]

    if choice == "accept":
        return build_accept_password(ts)
    if choice == "pam":
        return build_pam_open_session(ts)
    if choice == "failed":
        return build_failed_password(ts)
    if choice == "invalid":
        return build_invalid_user_failed(ts)
    return build_expected_service_noise(ts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux OS SSH baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending {args.count} Linux OS baseline events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print()

    ts = datetime.now(timezone.utc) - timedelta(minutes=5)

    for i in range(1, args.count + 1):
        ts += timedelta(seconds=random.randint(1, 6))
        pri, payload = build_event(ts)
        msg = wrap_syslog(ts, args.hostname, payload, pri)
        print(f"[{i:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Baseline events sent.")


if __name__ == "__main__":
    main()
