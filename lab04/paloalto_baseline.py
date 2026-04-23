#!/usr/bin/env python3
"""
Palo Alto PA Series baseline simulator for QRadar.

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
LOG_FORWARDER = "CorpForwarder"

SRC_IPS = [
    "10.10.20.24",
    "10.10.20.31",
    "10.10.21.18",
    "10.10.22.44",
    "10.10.23.15",
]

DESTS = [
    ("52.97.132.14", 443, "ssl", "business-and-economy", "alert", "OUTSIDE-ZN"),
    ("140.82.121.4", 443, "web-browsing", "computer-and-internet-info", "allow", "OUTSIDE-ZN"),
    ("104.18.32.7", 443, "ssl", "instant-messaging", "allow", "OUTSIDE-ZN"),
    ("142.250.183.14", 443, "ssl", "business-and-economy", "allow", "OUTSIDE-ZN"),
    ("151.101.1.69", 443, "web-browsing", "computer-and-internet-info", "allow", "OUTSIDE-ZN"),
    ("8.8.8.8", 53, "dns", "infrastructure-and-content-delivery-networks", "allow", "OUTSIDE-ZN"),
]

USERS = [
    r"acme\alice",
    r"acme\bob",
    r"acme\carol",
    r"acme\dave",
    r"acme\erin",
]

SOURCE_ZONE = "INSIDE-ZN"
INGRESS = "ethernet1/1"
EGRESS = "ethernet1/3"
VSYS = "vsys1"
DEVICE_NAME = "paloalto-pa01"


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


def build_traffic_event(ts: datetime) -> str:
    src = random.choice(SRC_IPS)
    dst, dst_port, application, url_cat, action, dst_zone = random.choice(DESTS)
    user = random.choice(USERS)
    src_port = random.randint(40000, 65000)
    proto = "udp" if dst_port == 53 else "tcp"
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
        "RuleName=Corp-Internet-Allow",
        f"usrName={user}",
        f"SourceUser={user}",
        "DestinationUser=",
        f"Application={application}",
        f"VirtualSystem={VSYS}",
        f"SourceZone={SOURCE_ZONE}",
        f"DestinationZone={dst_zone}",
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
        f"proto={proto}",
        f"action={action}",
        "ThreatID=",
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Palo Alto PA Series baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending {args.count} Palo Alto baseline events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print()

    ts = datetime.now(timezone.utc) - timedelta(minutes=5)

    for i in range(1, args.count + 1):
        ts += timedelta(seconds=random.randint(1, 6))
        payload = build_traffic_event(ts)
        msg = wrap_syslog(ts, args.hostname, payload)
        print(f"[{i:03d}] {msg}")
        send_syslog(args.qradar_host, args.port, msg)
        time.sleep(args.delay)

    print()
    print("[+] Baseline events sent.")


if __name__ == "__main__":
    main()
