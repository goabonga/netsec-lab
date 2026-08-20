# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-discovery: flag CDP/LLDP frames on the segment."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class DiscoveryWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Ether):
            return
        etype = pkt[s.Ether].type
        dst = pkt[s.Ether].dst.lower()
        if etype == 0x88CC:
            verdict("ALERT", f"LLDP frame from {pkt[s.Ether].src} -> discovery exposure")
        elif dst == "01:00:0c:cc:cc:cc":
            verdict("ALERT", f"CDP frame from {pkt[s.Ether].src} -> discovery exposure")

    def run(self, iface: str) -> None:
        print(f"[*] watching for CDP/LLDP on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    DiscoveryWatcher().run(args.iface)
    return 0
