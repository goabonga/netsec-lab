# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-hw-implant: a rogue device appears on the wire. LAB ONLY.

Emits traffic from an unsanctioned MAC - the software footprint of a dropped
implant or BadUSB network adapter. A real implant needs physical placement;
802.1X NAC / asset inventory (see inventory.py) blocks it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    frame = s.Ether(src=args.rogue_mac, dst="ff:ff:ff:ff:ff:ff") / s.IP(dst=args.dst) / s.ICMP()
    print(f"[*] rogue device {args.rogue_mac} announcing itself on {args.iface}")
    s.sendp(frame, iface=args.iface, count=args.count, verbose=0)
    verdict("ALERT", f"rogue device {args.rogue_mac} active")
    return 0
