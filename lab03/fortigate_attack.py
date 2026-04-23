#!/usr/bin/env python3
"""
Lab 01: Fortinet FortiGate attack simulator for QRadar.

Generates suspicious FortiGate traffic and threat-style events in a format
aligned to IBM QRadar's documented FortiGate sample event structure.
"""

import argparse
import random
import socket
import time
from datetime import datetime, timedelta

HOSTNAME = "fortigate01.acme-lab.local"
DEVID = "FGT60FTK19000001"
DEVNAME = "fortigate01"

SCENARIOS = {
    "all": "Run all suspicious FortiGate scenarios",
    "deny_burst": "Repeated denied outbound connections from one source",
    "port_scan": "One source hitting many destination ports",
    "suspicious_egress": "Outbound traffic to risky destinations and apps",
    "deny_then_allow": "Repeated denies followed by allowed access",
    "multi_host_same_destination": "Multiple internal hosts connecting to same suspicious destination",
}

ATTACKERS = [
    "10.10.99.45",
    "10.10.99.77",
    "10.10.99.88",
]

SUSPICIOUS_DESTS = [
    ("91.243.85.44", "Malicious.Site", "Botnet", "high"),
    ("185.220.101.14", "Tor", "Proxy.Avoidance", "high"),
    ("103.244.120.7", "Unknown", "Newly.Registered.Domains", "medium"),
]

SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080, 8443]
UNUSUAL_PORTS = [4444, 5555, 8081, 9001, 13389, 2222]


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


def build_traffic_event(ts: datetime, srcip: str, dstip: str, dstport: int, action: str,
                        service: str, app: str, appcat: str, apprisk: str,
                        policyid: int = 1, policyname: str = "Internet_Access") -> str:
    srcport = random.randint(40000, 65000)
    proto = 6
    duration = random.randint(1, 180)
    sentbyte = random.randint(100, 12000)
    rcvdbyte = random.randint(100, 20000)
    sentpkt = random.randint(1, 60)
    rcvdpkt = random.randint(1, 80)
    utmaction = "allow" if action in ("accept", "close") else "deny"

    return (
        f'date={fmt_date(ts)} time={fmt_time(ts)} '
        f'devname="{DEVNAME}" devid="{DEVID}" logid="0000000013" '
        f'type="traffic" subtype="forward" level="warning" vd="root" '
        f'eventtime={int(ts.timestamp() * 1000000000)} tz="+0000" '
        f'srcip={srcip} srcport={srcport} srcintf="internal" srcintfrole="lan" '
        f'dstip={dstip} dstport={dstport} dstintf="wan1" dstintfrole="wan" '
        f'srccountry="Reserved" dstcountry="Unknown" sessionid={random.randint(10000,99999)} '
        f'proto={proto} action="{action}" policyid={policyid} policytype="policy" '
        f'policyname="{policyname}" service="{service}" trandisp="snat" transip=172.16.72.26 '
        f'transport={srcport} appid={random.randint(1000,30000)} app="{app}" '
        f'appcat="{appcat}" apprisk="{apprisk}" applist="default" duration={duration} '
        f'sentbyte={sentbyte} rcvdbyte={rcvdbyte} sentpkt={sentpkt} rcvdpkt={rcvdpkt} '
        f'utmaction="{utmaction}" countapp=1'
    )


def emit_deny_burst(ts):
    srcip = ATTACKERS[0]
    for _ in range(50):
        dstip, app, appcat, apprisk = random.choice(SUSPICIOUS_DESTS)
        yield build_traffic_event(
            ts, srcip, dstip, random.choice([80, 443, 8080, 8443]),
            "deny", "HTTPS", app, appcat, apprisk,
            policyid=3, policyname="Restricted_Egress"
        )


def emit_port_scan(ts):
    srcip = ATTACKERS[1]
    dstip = "172.16.50.10"
    for port in SCAN_PORTS:
        for _ in range(3):
            yield build_traffic_event(
                ts, srcip, dstip, port,
                "deny", f"TCP/{port}", "Unknown", "Network.Service", "medium",
                policyid=4, policyname="Internal_Segmentation"
            )


def emit_suspicious_egress(ts):
    srcip = ATTACKERS[2]
    for _ in range(35):
        dstip, app, appcat, apprisk = random.choice(SUSPICIOUS_DESTS)
        yield build_traffic_event(
            ts, srcip, dstip, random.choice([443, 8080, 8443]),
            random.choice(["accept", "deny"]), "HTTPS", app, appcat, apprisk,
            policyid=5, policyname="Threat_Monitored_Egress"
        )


def emit_deny_then_allow(ts):
    srcip = ATTACKERS[0]
    dstip = "185.220.101.14"
    for _ in range(15):
        yield build_traffic_event(
            ts, srcip, dstip, 443,
            "deny", "HTTPS", "Tor", "Proxy.Avoidance", "high",
            policyid=3, policyname="Restricted_Egress"
        )
    for _ in range(8):
        yield build_traffic_event(
            ts, srcip, dstip, 443,
            "accept", "HTTPS", "Tor", "Proxy.Avoidance", "high",
            policyid=6, policyname="Bypass_Test"
        )


def emit_multi_host_same_destination(ts):
    dstip = "91.243.85.44"
    hosts = ["10.10.40.11", "10.10.40.12", "10.10.40.13", "10.10.40.14", "10.10.40.15"]
    for srcip in hosts:
        for _ in range(7):
            yield build_traffic_event(
                ts, srcip, dstip, 443,
                "accept", "HTTPS", "Malicious.Site", "Botnet", "high",
                policyid=5, policyname="Threat_Monitored_Egress"
            )


def emit_for_scenario(name, ts):
    if name == "deny_burst":
        yield from emit_deny_burst(ts)
    elif name == "port_scan":
        yield from emit_port_scan(ts)
    elif name == "suspicious_egress":
        yield from emit_suspicious_egress(ts)
    elif name == "deny_then_allow":
        yield from emit_deny_then_allow(ts)
    elif name == "multi_host_same_destination":
        yield from emit_multi_host_same_destination(ts)
    elif name == "all":
        for scenario in [
            "deny_burst",
            "port_scan",
            "suspicious_egress",
            "deny_then_allow",
            "multi_host_same_destination",
        ]:
            yield from emit_for_scenario(scenario, ts)


def main() -> None:
    parser = argparse.ArgumentParser(description="FortiGate attack simulator for QRadar")
    parser.add_argument("--qradar-host", required=True, help="QRadar or Event Collector IP/hostname")
    parser.add_argument("--port", type=int, default=514, help="Syslog UDP port")
    parser.add_argument("--hostname", default=HOSTNAME, help="Syslog hostname / log source identifier")
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="all", help="Attack scenario to send")
    parser.add_argument("--delay", type=float, default=0.03, help="Delay between events in seconds")
    args = parser.parse_args()

    print(f"[*] Sending FortiGate attack events to {args.qradar_host}:{args.port}")
    print(f"[*] Log Source Identifier: {args.hostname}")
    print(f"[*] Scenario: {args.scenario}")
    print()

    ts = datetime.utcnow() - timedelta(minutes=2)
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
