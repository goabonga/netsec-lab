# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-wifi-recon: WIDS rogue-AP detection."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core.sniffing import load_scapy

from netlab_wifi_recon.wids import Airspace


class RogueApWatcher:
    def __init__(self, known: set[str]) -> None:
        self._scapy = load_scapy()
        self.wids = Airspace(known_bssids={b.lower() for b in known})

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Dot11Beacon):
            return
        bssid = (pkt[s.Dot11].addr2 or "").lower()
        ssid = pkt[s.Dot11Elt].info.decode(errors="replace") if pkt.haslayer(s.Dot11Elt) else ""
        if bssid and bssid not in self.wids.seen:
            self.wids.observe(ssid, bssid)

    def run(self, iface: str) -> None:
        print(f"[*] WIDS on {iface}. known={self.wids.known_bssids or '(none)'}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    RogueApWatcher(set(args.known)).run(args.iface)
    return 0
