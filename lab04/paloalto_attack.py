#!/usr/bin/env python3
"""
Palo Alto PA Series attack simulator for QRadar.

Generates RFC3164 syslog-wrapped LEEF events aligned to IBM QRadar's
documented Palo Alto PA Series sample event structure.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta, timezone


HOSTNAME = "paloalto-pa01.acme-lab.local"
SERIAL = "001801010877"
PANOS_VERSION = "8.1.6"
LOG_FORWARDER = "ThreatForwarder"
DEVICE_NAME = "paloalto-pa01"
VSYS = "vsys1"
SOURCE_ZONE = "INSIDE-ZN"
INGRESS = "ethernet1/1"
EGRESS = "ethernet1/3"

SCENARIOS = {
    "all": "Run all suspicious scenarios",
    "threat_burst": "Repeated threat detections from one source",
    "port_sweep": "One source hitting many destination ports",
    "deny_then_allow": "Repeated denies followed by allowed access",
    "multi_host_same_destination": "Multiple hosts to same suspicious destination",
    "risky_url_category": "Repeated access to risky URL categories",
}

ATTACKERS = [
    ("10.10.99.45", r"acme\tempuser1"),
    ("10.10.99.77", r"acme\tempuser2"),
    ("10.10.99.88", r"acme\tempuser3"),
]

THREAT_DESTS = [
    ("91.243.85.44", 80, "web-browsing", "malware", "high"),
    ("185.220.101.14", 443, "ssl", "proxy-avoidance-and-anonymizers", "high"),
    ("103.244.120.7", 443, "ssl", "newly-registered-domain", "medium"),
]

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080, 8443]
THREAT_IDS = [
    ("spyware", "spyware/phish.eicar.test(100001)"),
    ("virus", "trojan/PDF.gen.eiez(268198686)"),
    ("vulnerability", "scan/port.sweep(200002)"),
]

SEVERITIES = ["medium", "high", "critical"]


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int = 180) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, message: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode("utf-8"), (host, port))
    sock.close()


def dev_time(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%b %d %Y %H:%M:%S GMT")


def recv_time(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y/%m/%d %H:%M:%S")


def build_threat_event(ts: datetime, src: str, user: str, dst: str, dst_port: int,
                       app: str, url_cat: str, subtype: str, threat_id: str,
                       severity: str, action: str = "alert") -> str:
    src_port = random.randint(40000, 65000)
    proto = "tcp"
    session_id = random.randint(1000, 9999999)

    leef_fields = [
        f"ReceiveTime={recv_time(ts)}",
        f"SerialNumber={SERIAL}",
        "cat=THREAT",
        f"Subtype={subtype}",
        f"devTime={dev_time(ts)}",
        f"src={src}",
        f"dst={dst}",
        f"srcPostNAT=172.16.68.{random.randint(10,99)}",
        f"dstPostNAT={dst}",
        "RuleName=Threat-Monitored-Egress",
        f"usrName={user}",
        f"SourceUser={user}",
        "DestinationUser=",
        f"Application={app}",
        f"VirtualSystem={VSYS}",
        f"SourceZone={SOURCE_ZONE}",
        "DestinationZone=OUTSIDE-ZN",
        f"IngressInterface={INGRESS}",
        f"EgressInterface={EGRESS}",
        f"LogForwardingProfile={LOG_FORWARDER}",
        f"SessionID={session_id}",
        "RepeatCount=1",
        f"srcPort={src_port}",
        f"dstPort={dst_port}",
        f"srcPostNATPort={random.randint(20000,65000)}",
        f"dstPostNATPort={dst_port}",
        "Flags=0x406000",
        f"proto={proto}",
        f"action={action}",
        f'Miscellaneous="suspicious object or URL"',
        f"ThreatID={threat_id}",
        f"URLCategory={url_cat}",
        f"sev={random.randint(3,8)}",
        f"Severity={severity}",
        "Direction=client-to-server",
        f"sequence={random.randint(1000000,999999999)}",
        "SourceLocation=10.0.0.0-10.255.255.255",
        "DestinationLocation=Internet",
        "ContentType=",
        "PCAP_ID=0",
        "FileDigest=",
        f"DeviceName={DEVICE_NAME}",
        "TunnelType=N/A",
        "ThreatCategory=generic",
    ]

    return (
        f"LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|{PANOS_VERSION}|{threat_id}|"
        + "|".join(leef_fields)
    )


def build_traffic_event(ts: datetime, src: str, user: str, dst: str, dst_port: int,
                        app: str, url_cat: str, action: str) -> str:
    src_port = random.randint(40000, 65000)
    proto = "tcp"
    session_id = random.randint(1000, 9999999)

    leef_fields = [
        f"ReceiveTime={recv_time(ts)}",
        f"SerialNumber={SERIAL}",
        "cat=TRAFFIC",
        "Subtype=forward",
        f"devTime={dev_time(ts)}",
        f"src={src}",
        f"dst={dst}",
        f"srcPostNAT=172.16.68.{random.randint(10,99)}",
        f"dstPostNAT={dst}",
        f"RuleName={'Threat-Monitored-Egress' if action == 'allow' else 'Restricted-Egress'}",
        f"usrName={user}",
        f"SourceUser={user}",
        "DestinationUser=",
        f"Application={app}",
        f"VirtualSystem={VSYS}",
        f"SourceZone={SOURCE_ZONE}",
        "DestinationZone=OUTSIDE-ZN",
        f"IngressInterface={INGRESS}",
        f"EgressInterface={EGRESS}",
        f"LogForwardingProfile={LOG_FORWARDER}",
        f"SessionID={session_id}",
        "RepeatCount=1",
        f"srcPort={src_port}",
        f"dstPort={dst_port}",
        f"srcPostNATPort={random.randint(20000,65000)}",
        f"dstPostNATPort={dst_port}",
        "Flags=0x400000",
        "proto=tcp",
        f"action={action}",
        f"URLCategory={url_cat}",
        "Severity=informational",
        "Direction=client-to-server",
        f"sequence={random.randint(1000000,999999999)}",
        "SourceLocation=10.0.0.0-10.255.255.255",
        "DestinationLocation=Internet",
        f"DeviceName={DEVICE_NAME}",
        "TunnelType=N/A",
    ]

    return (
        f"LEEF:1.0|Palo Alto Networks|PAN-OS Syslog Integration|{PANOS_VERSION}|TRAFFIC|"
        + "|".join(leef_fields)
    )


def emit_threat_burst(ts):
    src, user = ATTACKERS[0]
    for _ in range(45):
        dst, dst_port, app, url_cat, severity = random.choice(THREAT_DESTS)
        subtype, threat_id = random.choice(THREAT_IDS)
        yield build_threat_event(ts, src, user, dst, dst_port, app, url_cat, subtype, threat_id, severity, "alert")


def emit_port_sweep(ts):
    src, user = ATTACKERS[1]
    dst = "172.16.50.10"
    for port in SCAN_PORTS:
        for _ in range(3):
            yield build_traffic_event(ts, src, user, dst, port, "incomplete", "unknown", "deny")


def emit_deny_then_allow(ts):
    src, user = ATTACKERS[2]
    dst, dst_port, app, url_cat, _ = THREAT_DESTS[1]
    for _ in range(15):
        yield build_traffic_event(ts, src, user, dst, dst_port, app, url_cat, "deny")
    for _ in range(8):
        yield build_traffic_event(ts, src, user, dst, dst_port, app, url_cat, "allow")


def emit_multi_host_same_destination(ts):
    dst, dst_port, app, url_cat, severity = THREAT_DESTS[0]
    users = [r"acme\hosta", r"acme\hostb", r"acme\hostc", r"acme\hostd", r"acme\hoste"]
    srcs = ["10.10.40.11", "10.10.40.12", "10.10.40.13", "10.10.40.14", "10.10.40.15"]
    for src, user in zip(srcs, users):
        for _ in range(7):
            yield build_threat_event(ts, src, user, dst, dst_port, app, url_cat, "spyware", "spyware/c2.generic(300001)", severity, "alert")


def emit_risky_url_category(ts):
    src, user = ATTACKERS[0]
    for _ in range(35):
        dst, dst_port, app, url_cat, severity = random.choice(THREAT_DESTS)
        yield build_traffic_event(ts, src, user, dst, dst_port, app, url_cat, random.choice(["allow", "alert", "deny"]))


def emit_for_scenario(name, ts):
    if name == "threat_burst":
        yield from emit_threat_burst(ts)
    elif name == "port_sweep":
        yield from emit_port_sweep(ts)
    elif name == "deny_then_allow":
        yield from emit_deny_then_allow(ts)
    elif name == "multi_host_same_destination":
        yield from emit_multi_host_same_destination(ts)
    elif name == "risky_url_category":
        yield from emit_risky_url_category(ts)
    elif name == "all":
        for scenario in [
            "threat_burst",
            "port_sweep",
            "deny_then_allow",
            "multi_host_same_destination",
            "risky_url_category",
        ]:
            yield from emit_for_scenario(scenario, ts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Palo Alto PA Series attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending Palo Alto attack events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print(f"[*] Scenario: {args.scenario}")
    print()

    ts = datetime.now(timezone.utc) - timedelta(minutes=2)
    seq = 0

    for payload in emit_for_scenario(args.scenario, ts):
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
