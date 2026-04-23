#!/usr/bin/env python3
"""
Lab 01: Fortinet FortiGate baseline simulator for QRadar.

Generates RFC3164 syslog-wrapped FortiGate traffic logs in a format aligned to
IBM QRadar's documented FortiGate sample event structure.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta

HOSTNAME = "fortigate01.acme-lab.local"
DEVID = "FGT60FTK19000001"
DEVNAME = "fortigate01"

SRC_IPS = [
    "10.10.20.24",
    "10.10.20.31",
    "10.10.21.18",
    "10.10.22.44",
    "10.10.23.15",
]

DESTINATIONS = [
    ("52.97.132.14", 443, "HTTPS", "Microsoft.Office365", "Business", "low"),
    ("140.82.121.4", 443, "HTTPS", "GitHub", "Information.Technology", "low"),
    ("104.18.32.7", 443, "HTTPS", "Slack", "Instant.Messaging", "low"),
    ("142.250.183.14", 443, "HTTPS", "Google.Docs", "Business", "low"),
    ("151.101.1.69", 443, "HTTPS", "Developer_Docs", "Information.Technology", "low"),
    ("8.8.8.8", 53, "DNS", "DNS", "Infrastructure", "low"),
]

ACTIONS = ["accept", "accept", "accept", "close"]
INTERFACES = [("internal", "lan", "wan1", "wan")]
COUNTRIES = ["Reserved", "United States", "India", "Singapore"]


def rfc3164_timestamp(ts: datetime) -> str:
    day = ts.strftime("%d").lstrip("0") or "0"
    return f"{ts.strftime('%b')} {day:>2} {ts.strftime('%H:%M:%S')}"


def wrap_syslog(ts: datetime, hostname: str, payload: str, pri: int = 134) -> str:
    return f"<{pri}>{rfc3164_timestamp(ts)} {hostname} {payload}"


def send_syslog(host: str, port: int, msg: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg.encode("utf-8"), (host, port))
    sock.close()


def fmt_date(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d")


def fmt_time(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def build_event(ts: datetime) -> str:
    srcip = random.choice(SRC_IPS)
    dstip, dstport, service, app, appcat, apprisk = random.choice(DESTINATIONS)
    srcport = random.randint(40000, 65000)
    sessionid = random.randint(10000, 99999)
    proto = 6 if dstport != 53 else 17
    action = random.choice(ACTIONS)
    duration = random.randint(10, 600)
    sentbyte = random.randint(500, 15000)
    rcvdbyte = random.randint(800, 25000)
    sentpkt = random.randint(5, 120)
    rcvdpkt = random.randint(5, 160)
    srcintf, srcrole, dstintf, dstrole = INTERFACES[0]

    return (
        f'date={fmt_date(ts)} time={fmt_time(ts)} '
        f'devname="{DEVNAME}" devid="{DEVID}" logid="0000000013" '
        f'type="traffic" subtype="forward" level="notice" vd="root" '
        f'eventtime={int(ts.timestamp() * 1000000000)} tz="+0000" '
        f'srcip={srcip} srcport={srcport} srcintf="{srcintf}" srcintfrole="{srcrole}" '
        f'dstip={dstip} dstport={dstport} dstintf="{dstintf}" dstintfrole="{dstrole}" '
        f'srccountry="{random.choice(COUNTRIES)}" dstcountry="{random.choice(COUNTRIES)}" '
        f'sessionid={sessionid} proto={proto} action="{action}" policyid=1 '
        f'policytype="policy" policyname="Internet_Access" service="{service}" '
        f'trandisp="snat" transip=172.16.72.26 transport={srcport} '
        f'appid={random.randint(1000, 30000)} app="{app}" appcat="{appcat}" '
        f'apprisk="{apprisk}" applist="default" duration={duration} '
        f'sentbyte={sentbyte} rcvdbyte={rcvdbyte} sentpkt={sentpkt} rcvdpkt={rcvdpkt} '
        f'utmaction="allow" countapp=1'
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="FortiGate baseline simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--count", type=int, default=200, help="Number of events to send")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending {args.count} FortiGate baseline events to {args.qradar_host}:{args.port}")
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
