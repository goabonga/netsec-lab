# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-macsec: attempt to inject a frame onto a link. LAB ONLY.

Emits a forged Ethernet frame. On a MACsec-protected link (see link.py) it fails
the integrity check and is dropped; on a cleartext link it is accepted - which is
exactly why MACsec is deployed.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    frame = s.Ether(dst="ff:ff:ff:ff:ff:ff") / s.IP(dst=args.dst) / s.ICMP()
    print(
        f"[*] injecting a forged frame on {args.iface} (dropped by MACsec, accepted on cleartext)"
    )
    s.sendp(frame, iface=args.iface, count=args.count, verbose=0)
    verdict("ALERT", "injection attempt sent")
    return 0
