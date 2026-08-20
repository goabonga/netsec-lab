# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-vrrp-hsrp: flag a VRRP priority change / preemption."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class VrrpWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.best: dict[int, int] = {}  # vrid -> best priority seen

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.VRRP):
            return
        v = pkt[s.VRRP]
        prev = self.best.get(v.vrid)
        if prev is not None and v.priority > prev:
            src = pkt[s.IP].src if pkt.haslayer(s.IP) else "?"
            verdict("ALERT", f"vrid {v.vrid} priority {v.priority} from {src} -> MASTER TAKEOVER")
        self.best[v.vrid] = max(prev or 0, v.priority)

    def run(self, iface: str) -> None:
        print(f"[*] watching VRRP on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="vrrp or proto 112", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    VrrpWatcher().run(args.iface)
    return 0
