#!/usr/bin/env python3
"""
Lab 09: F5 Networks BIG-IP APM baseline simulator for QRadar.

Generates RFC3164 syslog-wrapped F5 BIG-IP APM style events in a format aligned
to IBM QRadar's documented sample event structure.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta

HOSTNAME = "f5-apm01.acme-lab.local"

CLIENTS = [
    ("10.40.10.21", "alice"),
    ("10.40.10.22", "bob"),
    ("10.40.10.23", "carol"),
    ("10.40.10.24", "dave"),
    ("10.40.10.25", "erin"),
]

DESTINATIONS = [
    ("172.16.10.20", 443),
    ("172.16.10.21", 443),
    ("172.16.20.15", 8443),
    ("172.16.30.11", 3389),
    ("172.16.40.25", 22),
]

POLICIES = [
    "/Common/corp_access_policy",
    "/Common/remote_user_policy",
]

ACLS = [
    "/Common/allow_https_apps",
    "/Common/allow_rdp_admin",
    "/Common/allow_ssh_ops",
]

PROTO = ["tcp", "tcp", "tcp", "udp"]

RESULTS = [
    ("allow", "notice", "01580002:5:"),
    ("allow", "notice", "01580002:5:"),
    ("allow", "notice", "01580002:5:"),
    ("deny", "warning", "01580001:5:"),
]

USER_AGENT_HINTS = [
    "vpn-session-normal",
    "corp-laptop",
    "managed-endpoint",
]


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int = 173) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, msg: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode("utf-8"), (host, port))
    sock.close()


def session_id() -> str:
    alphabet = "abcdef0123456789"
    return "".join(random.choice(alphabet) for _ in range(8))


def build_event(ts: datetime) -> str:
    src_ip, username = random.choice(CLIENTS)
    dst_ip, dst_port = random.choice(DESTINATIONS)
    src_port = random.randint(40000, 65000)
    policy = random.choice(POLICIES)
    acl = random.choice(ACLS)
    proto = random.choice(PROTO)
    action, severity_word, code = random.choice(RESULTS)
    tmm_pid = random.randint(12000, 26000)
    acl_rule = random.randint(1, 8)

    # Follows IBM-documented structure:
    # <pri>timestamp host notice tmm[pid]: 01580002:5: /policy:Common:session: allow ACL: /acl:rule packet: tcp src:port -> dst:port
    return (
        f"{severity_word} tmm[{tmm_pid}]: {code} "
        f"{policy}:Common:{session_id()}: {action} ACL: "
        f"{acl}:{acl_rule} packet: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"user={username} endpoint={random.choice(USER_AGENT_HINTS)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="F5 BIG-IP APM baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending {args.count} F5 BIG-IP APM baseline events to {args.qradar_host}:{args.port}")
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
