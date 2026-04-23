#!/usr/bin/env python3
"""
Lab 08: Fortinet FortiMail baseline simulator for QRadar.

Generates RFC3164 syslog-wrapped FortiMail-style events in formats aligned
to IBM QRadar FortiMail sample messages.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta

DEVICE_ID = "FE100C3909600504"
HOSTNAME = "fortimail01.acme-lab.local"

SMTP_CLIENTS = [
    "10.20.30.11",
    "10.20.30.12",
    "10.20.30.13",
    "10.20.30.14",
    "10.20.30.15",
]

MAIL_SERVERS = [
    "172.16.50.10",
    "172.16.50.11",
    "172.16.50.12",
]

SENDERS = [
    "alerts@acme.com",
    "hr@acme.com",
    "it-notify@acme.com",
    "billing@acme.com",
    "noreply@acme.com",
]

RECIPIENTS = [
    "alice@acme.com",
    "bob@acme.com",
    "carol@acme.com",
    "dave@acme.com",
    "finance@acme.com",
    "security@acme.com",
]

SUBJECTS = [
    "Monthly payslip",
    "Security awareness reminder",
    "Invoice available",
    "Password expiry notice",
    "Team calendar update",
    "Benefits enrollment information",
]

CLASSIFIERS = ["0x11", "0x17", "0x21", "0x25"]
MAILERS = ["proxy", "smtp", "submission"]


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int = 134) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, msg: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode("utf-8"), (host, port))
    sock.close()


def fm_date(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d")


def fm_time(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def session_id(prefix: str = "q6K") -> str:
    a = random.randint(100000, 999999)
    b = random.randint(100000, 999999)
    return f"{prefix}{a}-{prefix}{b}"


def build_statistics_event(ts: datetime) -> str:
    return (
        f'date={fm_date(ts)} time={fm_time(ts)} device_id={DEVICE_ID} '
        f'log_id=0200025843 type=statistics pri=information '
        f'session_id="{session_id("r1PF")}" '
        f'client_name="{random.choice(SMTP_CLIENTS)}" '
        f'dst_ip="{random.choice(MAIL_SERVERS)}" endpoint="" '
        f'from="{random.choice(SENDERS)}" to="{random.choice(RECIPIENTS)}" '
        f'polid="0:1:0" domain="acme.com" '
        f'subject="{random.choice(SUBJECTS)}" '
        f'mailer="{random.choice(MAILERS)}" transfer_time="{random.randint(1,12)}" '
        f'scan_time="{random.randint(1,7)}" resolved="" direction="outbound" '
        f'virus="" disposition="0x200" classifier="{random.choice(CLASSIFIERS)}" '
        f'message_length="{random.randint(18000,250000)}"'
    )


def build_kevent_login(ts: datetime) -> str:
    admin_user = random.choice(["admin", "secops", "mailadmin"])
    src = random.choice(["10.20.40.5", "10.20.40.8", "10.20.40.9"])
    return (
        f'date={fm_date(ts)} time={fm_time(ts)} device_id={DEVICE_ID} '
        f'log_id=0000000920 type=kevent subtype=config pri=information '
        f'user={admin_user} ui={src} module=system submodule=cli '
        f'msg="user {admin_user} login successfully from CLI"'
    )


def build_webmail_event(ts: datetime) -> str:
    sender = random.choice(SENDERS)
    recipient = random.choice(RECIPIENTS)
    src = random.choice(SMTP_CLIENTS)
    return (
        f'date={fm_date(ts)} time={fm_time(ts)} device_id=FE10333504 '
        f'log_id=103032255 type=event subtype=webmail pri=information '
        f'from="{sender}" to="{recipient}" src={src} '
        f'session_id="{session_id("333")}" '
        f'msg="User {sender} from {src} logged in"'
    )


def build_event(ts: datetime) -> str:
    choice = random.choices(
        population=["statistics", "statistics", "statistics", "kevent", "webmail"],
        weights=[45, 45, 45, 8, 6],
        k=1,
    )[0]

    if choice == "statistics":
        return build_statistics_event(ts)
    if choice == "kevent":
        return build_kevent_login(ts)
    return build_webmail_event(ts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fortinet FortiMail baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending {args.count} FortiMail baseline events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print()

    ts = datetime.utcnow() - timedelta(minutes=5)

    for i in range(1, args.count + 1):
        ts += timedelta(seconds=random.randint(1, 6))
        payload = build_event(ts)
        msg = wrap_syslog(ts, args.hostname, payload)
        print(f"[{i:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Baseline events sent.")


if __name__ == "__main__":
    main()
