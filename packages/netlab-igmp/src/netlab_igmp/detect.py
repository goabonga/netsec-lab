# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-igmp: flag joins to sensitive multicast groups."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class IgmpWatcher:
    def __init__(self, sensitive: set[str]) -> None:
        self._scapy = load_scapy()
        self.sensitive = sensitive

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.IGMP):
            return
        igmp = pkt[s.IGMP]
        if igmp.type == 0x16 and igmp.gaddr in self.sensitive:
            src = pkt[s.IP].src if pkt.haslayer(s.IP) else "?"
            verdict("ALERT", f"{src} joined sensitive group {igmp.gaddr} -> multicast eavesdrop")

    def run(self, iface: str) -> None:
        print(f"[*] watching IGMP joins on {iface}. sensitive={self.sensitive}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="igmp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    IgmpWatcher(set(args.sensitive)).run(args.iface)
    return 0
