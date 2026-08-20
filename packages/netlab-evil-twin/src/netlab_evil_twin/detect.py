# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-evil-twin: flag a known SSID on an unknown BSSID."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core.sniffing import load_scapy

from netlab_evil_twin.ess import EssMonitor


class TwinWatcher:
    def __init__(self, ssid: str, legit_bssids: set[str]) -> None:
        self._scapy = load_scapy()
        self.ssid = ssid
        self.mon = EssMonitor(legit={ssid: {b.lower() for b in legit_bssids}})
        self._seen: set[str] = set()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Dot11Beacon) or not pkt.haslayer(s.Dot11Elt):
            return
        ssid = pkt[s.Dot11Elt].info.decode(errors="replace")
        bssid = (pkt[s.Dot11].addr2 or "").lower()
        if ssid == self.ssid and bssid not in self._seen:
            self._seen.add(bssid)
            self.mon.observe(ssid, bssid)

    def run(self, iface: str) -> None:
        print(f"[*] watching for '{self.ssid}' twins on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    TwinWatcher(args.ssid, set(args.legit)).run(args.iface)
    return 0
