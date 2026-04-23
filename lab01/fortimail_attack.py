#!/usr/bin/env python3
"""
Lab 08: Fortinet FortiMail attack simulator for QRadar.

Generates suspicious FortiMail-style events in formats aligned to IBM QRadar
FortiMail sample messages.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta

DEVICE_ID = "FE100C3909600504"
HOSTNAME = "fortimail01.acme-lab.local"

ATTACKER_IPS = [
    "185.220.101.14",
    "91.243.85.44",
    "103.244.120.7",
]

MAIL_SERVERS = [
    "172.16.50.10",
    "172.16.50.11",
]

TARGETS = [
    "alice@acme.com",
    "bob@acme.com",
    "carol@acme.com",
    "dave@acme.com",
    "finance@acme.com",
    "security@acme.com",
    "hr@acme.com",
]

SUSPICIOUS_SENDERS = [
    "payroll-update@secure-payroll-mail.com",
    "mfa-reset@acme-login-help.com",
    "benefits@acme-benifits.com",
    "invoice@trusted-billing-mail.net",
]

PHISH_SUBJECTS = [
    "Urgent Payroll Action Required",
    "MFA Reset Verification Needed",
    "Invoice Attached Please Review",
    "Updated Benefits Form",
]

MALWARE_MESSAGES = [
    'msg="The file invoice-0416.zip is infected with EICAR_TEST_FILE."',
    'msg="The file payslip_april.docm is infected with EICAR_TEST_FILE."',
    'msg="The file secure_message.html is infected with EICAR_TEST_FILE."',
]


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


def build_spam_campaign(ts: datetime) -> str:
    return (
        f'date={fm_date(ts)} time={fm_time(ts)} device_id=FEccc504 '
        f'log_id=0000 type=spam pri=information '
        f'session_id="{session_id("q6K")}" '
        f'client_name="[{random.choice(ATTACKER_IPS)}]" '
        f'dst_ip="{random.choice(MAIL_SERVERS)}" '
        f'from="{random.choice(SUSPICIOUS_SENDERS)}" '
        f'to="{random.choice(TARGETS)}" '
        f'subject="{random.choice(PHISH_SUBJECTS)}" '
        f'msg="Detected by BannedWord test"'
    )


def build_malware_attachment(ts: datetime) -> str:
    return (
        f'date={fm_date(ts)} time={fm_time(ts)} device_id=FE1055500504 '
        f'log_id=100000924 type=virus subtype=infected pri=information '
        f'from="{random.choice(SUSPICIOUS_SENDERS)}" '
        f'to="{random.choice(TARGETS)}" '
        f'src={random.choice(ATTACKER_IPS)} '
        f'session_id="{session_id("q6OL")}" '
        f'{random.choice(MALWARE_MESSAGES)}'
    )


def build_webmail_abuse(ts: datetime) -> str:
    src = random.choice(ATTACKER_IPS)
    victim = random.choice(TARGETS)
    return (
        f'date={fm_date(ts)} time={fm_time(ts)} device_id=FE10333504 '
        f'log_id=103032255 type=event subtype=webmail pri=information '
        f'from="{victim}" to="{victim}" src={src} '
        f'session_id="{session_id("333")}" '
        f'msg="User testUser from {src} logged in"'
    )


SCENARIOS = {
    "all": "All suspicious mail scenarios",
    "spam_campaign": "Phishing or spam wave to multiple users",
    "malware_attachment": "Malicious attachment detections",
    "webmail_abuse": "Suspicious webmail login activity",
}


def emit_events_for_scenario(name: str, ts: datetime):
    if name == "spam_campaign":
        for _ in range(60):
            yield build_spam_campaign(ts)
    elif name == "malware_attachment":
        for _ in range(30):
            yield build_malware_attachment(ts)
    elif name == "webmail_abuse":
        for _ in range(25):
            yield build_webmail_abuse(ts)
    elif name == "all":
        for _ in range(40):
            yield build_spam_campaign(ts)
        for _ in range(20):
            yield build_malware_attachment(ts)
        for _ in range(15):
            yield build_webmail_abuse(ts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fortinet FortiMail attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending FortiMail attack events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print(f"[*] Scenario: {args.scenario}")
    print()

    ts = datetime.utcnow() - timedelta(minutes=2)
    seq = 0

    for payload in emit_events_for_scenario(args.scenario, ts):
        ts += timedelta(seconds=random.uniform(0.3, 2.0))
        seq += 1
        msg = wrap_syslog(ts, args.hostname, payload)
        print(f"[{seq:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Attack events sent.")


if __name__ == "__main__":
    main()
