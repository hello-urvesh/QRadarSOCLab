#!/usr/bin/env python3
"""
Lab 09: F5 Networks BIG-IP APM attack simulator for QRadar.

Generates suspicious F5 BIG-IP APM style events in a format aligned to IBM
QRadar's documented sample event structure.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta

HOSTNAME = "f5-apm01.acme-lab.local"

SCENARIOS = {
    "all": "Run all suspicious APM scenarios",
    "acl_deny_burst": "Burst of denied ACL hits from one remote client",
    "rdp_target_sweep": "One client sweeping multiple internal RDP targets",
    "nonstandard_port_tunneling": "Access attempts to unusual internal ports",
    "deny_then_allow": "Repeated denies followed by allowed access to same destination",
    "multi_user_sensitive_server": "Multiple users converging on same sensitive host",
}

ATTACKERS = [
    ("185.220.101.14", "unknown1"),
    ("91.243.85.44", "unknown2"),
    ("103.244.120.7", "unknown3"),
]

SENSITIVE_TARGETS = [
    ("172.16.30.11", 3389),
    ("172.16.30.12", 3389),
    ("172.16.30.13", 3389),
    ("172.16.40.25", 22),
    ("172.16.50.10", 8443),
]

UNUSUAL_PORTS = [4444, 5555, 8081, 9001, 13389, 2222]

POLICY = "/Common/remote_user_policy"
DENY_ACL = "/Common/restricted_segments"
ALLOW_ACL = "/Common/approved_access"


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


def format_event(src_ip: str, dst_ip: str, src_port: int, dst_port: int, username: str,
                 action: str, severity_word: str, code: str, acl: str, acl_rule: int,
                 proto: str = "tcp") -> str:
    tmm_pid = random.randint(12000, 26000)
    return (
        f"{severity_word} tmm[{tmm_pid}]: {code} "
        f"{POLICY}:Common:{session_id()}: {action} ACL: "
        f"{acl}:{acl_rule} packet: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
        f"user={username} endpoint=vpn-session-anomalous"
    )


def acl_deny_burst():
    src_ip, username = ATTACKERS[0]
    dst_ip, _ = random.choice(SENSITIVE_TARGETS)
    for _ in range(50):
        yield format_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=random.choice([22, 3389, 8443]),
            username=username,
            action="deny",
            severity_word="warning",
            code="01580001:5:",
            acl=DENY_ACL,
            acl_rule=random.randint(1, 4),
        )


def rdp_target_sweep():
    src_ip, username = ATTACKERS[0]
    for dst_ip, dst_port in SENSITIVE_TARGETS[:4]:
        for _ in range(10):
            yield format_event(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(40000, 65000),
                dst_port=dst_port,
                username=username,
                action="allow",
                severity_word="notice",
                code="01580002:5:",
                acl=ALLOW_ACL,
                acl_rule=2,
            )


def nonstandard_port_tunneling():
    src_ip, username = ATTACKERS[1]
    for _ in range(35):
        dst_ip = random.choice(["172.16.70.10", "172.16.70.11", "172.16.80.25"])
        yield format_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=random.choice(UNUSUAL_PORTS),
            username=username,
            action=random.choice(["allow", "deny"]),
            severity_word=random.choice(["notice", "warning"]),
            code=random.choice(["01580002:5:", "01580001:5:"]),
            acl=random.choice([ALLOW_ACL, DENY_ACL]),
            acl_rule=random.randint(1, 6),
        )


def deny_then_allow():
    src_ip, username = ATTACKERS[2]
    dst_ip, dst_port = ("172.16.50.10", 8443)
    for _ in range(15):
        yield format_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=dst_port,
            username=username,
            action="deny",
            severity_word="warning",
            code="01580001:5:",
            acl=DENY_ACL,
            acl_rule=1,
        )
    for _ in range(8):
        yield format_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(40000, 65000),
            dst_port=dst_port,
            username=username,
            action="allow",
            severity_word="notice",
            code="01580002:5:",
            acl=ALLOW_ACL,
            acl_rule=3,
        )


def multi_user_sensitive_server():
    dst_ip, dst_port = ("172.16.30.11", 3389)
    users = ["alice", "bob", "carol", "dave", "erin"]
    srcs = ["10.60.10.11", "10.60.10.12", "10.60.10.13", "10.60.10.14", "10.60.10.15"]
    for src_ip, username in zip(srcs, users):
        for _ in range(8):
            yield format_event(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(40000, 65000),
                dst_port=dst_port,
                username=username,
                action="allow",
                severity_word="notice",
                code="01580002:5:",
                acl=ALLOW_ACL,
                acl_rule=2,
            )


def emit_for_scenario(name: str):
    if name == "acl_deny_burst":
        yield from acl_deny_burst()
    elif name == "rdp_target_sweep":
        yield from rdp_target_sweep()
    elif name == "nonstandard_port_tunneling":
        yield from nonstandard_port_tunneling()
    elif name == "deny_then_allow":
        yield from deny_then_allow()
    elif name == "multi_user_sensitive_server":
        yield from multi_user_sensitive_server()
    elif name == "all":
        for scenario in [
            "acl_deny_burst",
            "rdp_target_sweep",
            "nonstandard_port_tunneling",
            "deny_then_allow",
            "multi_user_sensitive_server",
        ]:
            yield from emit_for_scenario(scenario)


def main() -> None:
    parser = argparse.ArgumentParser(description="F5 BIG-IP APM attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending F5 BIG-IP APM attack events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print(f"[*] Scenario: {args.scenario}")
    print()

    ts = datetime.utcnow() - timedelta(minutes=2)
    seq = 0

    for payload in emit_for_scenario(args.scenario):
        ts += timedelta(seconds=random.uniform(0.2, 1.5))
        seq += 1
        msg = wrap_syslog(ts, args.hostname, payload)
        print(f"[{seq:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Attack events sent.")


if __name__ == "__main__":
    main()
