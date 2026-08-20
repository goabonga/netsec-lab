# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-hw-implant: flag devices outside the asset inventory."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core.sniffing import load_scapy

from netlab_hw_implant.inventory import AssetInventory


class ImplantWatcher:
    def __init__(self, known: set[str]) -> None:
        self._scapy = load_scapy()
        self.inv = AssetInventory(known={m.lower() for m in known})
        self._seen: set[str] = set()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Ether):
            return
        mac = pkt[s.Ether].src.lower()
        if mac not in self._seen:
            self._seen.add(mac)
            self.inv.observe(mac)

    def run(self, iface: str) -> None:
        print(f"[*] NAC watch on {iface}. known={self.inv.known or '(none)'}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    ImplantWatcher(set(args.known)).run(args.iface)
    return 0
