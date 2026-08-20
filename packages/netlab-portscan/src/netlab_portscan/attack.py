# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-portscan: SYN / FIN / NULL / Xmas port scan. LAB ONLY.

Probes a port range and reads the responses: a SYN scan reads SYN/ACK (open) vs
RST (closed); FIN/NULL/Xmas scans rely on closed ports sending RST while open
ports stay silent. Scan detection + rate-limiting (see scandet.py) contain it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

_FLAGS = {"syn": "S", "fin": "F", "null": "", "xmas": "FPU"}


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    flags = _FLAGS[args.type]
    ports = list(range(args.start, args.end + 1))
    print(f"[*] {args.type} scan of {args.dst}:{args.start}-{args.end}")
    ans, _ = s.sr(
        s.IP(dst=args.dst) / s.TCP(dport=ports, flags=flags), timeout=args.timeout, verbose=0
    )
    for _snd, rcv in ans:
        if rcv.haslayer(s.TCP) and rcv[s.TCP].flags & 0x12 == 0x12:  # SYN/ACK
            verdict("ALERT", f"port {rcv[s.TCP].sport} OPEN")
    verdict("INFO", f"scan complete ({len(ports)} ports)")
    return 0
