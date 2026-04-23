#!/usr/bin/env python3
"""
Linux OS attack simulator for QRadar.

Use case:
Service account interactive SSH login.

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

SCENARIOS = {
    "all": "Run all suspicious Linux SSH scenarios",
    "service_account_success": "Interactive SSH success using service accounts",
    "service_account_failure_burst": "Repeated failed SSH attempts using service accounts",
    "service_account_multi_source": "Same service account used from multiple remote IPs",
    "service_account_pam_sequence": "Accepted SSH followed by PAM session open for service account",
}

SERVICE_ACCOUNTS = [
    "svc_backup",
    "svc_monitor",
    "svc_deploy",
    "svc_batch",
]

UNTRUSTED_IPS = [
    "185.220.101.14",
    "91.243.85.44",
    "103.244.120.7",
    "45.142.214.33",
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


def failed_password(user: str, src_ip: str) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    src_port = random.randint(40000, 65000)
    payload = (
        f"sshd[{pid}]: Failed password for {user} from {src_ip} "
        f"port {src_port} ssh2"
    )
    return PRIORITY_FAILED, payload


def accept_password(user: str, src_ip: str) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    src_port = random.randint(40000, 65000)
    payload = (
        f"sshd[{pid}]: Accepted password for {user} from {src_ip} "
        f"port {src_port} ssh2"
    )
    return PRIORITY_INFO, payload


def pam_open_session(user: str) -> tuple[int, str]:
    pid = random.randint(1000, 50000)
    payload = (
        f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} "
        f"by (uid=0)"
    )
    return PRIORITY_PAM, payload


def emit_service_account_success():
    user = random.choice(SERVICE_ACCOUNTS)
    src_ip = random.choice(UNTRUSTED_IPS)
    for _ in range(25):
        yield accept_password(user, src_ip)


def emit_service_account_failure_burst():
    user = random.choice(SERVICE_ACCOUNTS)
    src_ip = random.choice(UNTRUSTED_IPS)
    for _ in range(40):
        yield failed_password(user, src_ip)


def emit_service_account_multi_source():
    user = random.choice(SERVICE_ACCOUNTS)
    for src_ip in UNTRUSTED_IPS:
        for _ in range(10):
            yield accept_password(user, src_ip)


def emit_service_account_pam_sequence():
    user = random.choice(SERVICE_ACCOUNTS)
    src_ip = random.choice(UNTRUSTED_IPS)
    for _ in range(15):
        yield accept_password(user, src_ip)
        yield pam_open_session(user)


def emit_for_scenario(name: str):
    if name == "service_account_success":
        yield from emit_service_account_success()
    elif name == "service_account_failure_burst":
        yield from emit_service_account_failure_burst()
    elif name == "service_account_multi_source":
        yield from emit_service_account_multi_source()
    elif name == "service_account_pam_sequence":
        yield from emit_service_account_pam_sequence()
    elif name == "all":
        for scenario in [
            "service_account_success",
            "service_account_failure_burst",
            "service_account_multi_source",
            "service_account_pam_sequence",
        ]:
            yield from emit_for_scenario(scenario)


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux OS service account SSH attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending Linux OS attack events to {args.qradar_host}:{args.port}")
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
