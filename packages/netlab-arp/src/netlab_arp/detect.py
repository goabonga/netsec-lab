# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-arp: watch for ARP cache poisoning.

Tracks the IP -> MAC mapping seen on the wire; when an IP suddenly resolves to a
different MAC (or one MAC claims many IPs) that is the signature of poisoning.
The host-side counterpart of Dynamic ARP Inspection.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class ArpWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.ip_to_mac: dict[str, str] = {}

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.ARP) or pkt[s.ARP].op != 2:
            return
        ip, mac = pkt[s.ARP].psrc, pkt[s.ARP].hwsrc
        prev = self.ip_to_mac.get(ip)
        if prev and prev != mac:
            verdict("ALERT", f"{ip} moved {prev} -> {mac} -> ARP CACHE POISONING")
        elif prev is None:
            verdict("LEARN", f"{ip} is at {mac}")
        self.ip_to_mac[ip] = mac

    def run(self, iface: str) -> None:
        print(f"[*] watching ARP on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="arp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    ArpWatcher().run(args.iface)
    return 0
