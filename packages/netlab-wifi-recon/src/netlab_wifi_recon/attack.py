# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-wifi-recon: passive 802.11 airspace harvesting. LAB ONLY.

Sniffs beacons and probe requests on a monitor-mode interface to map APs, their
SSIDs/BSSIDs and the clients probing for known networks - no frame is sent.
Requires a Wi-Fi NIC in monitor mode; not replayable in the netns lab.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class Harvester:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.aps: dict[str, str] = {}

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.Dot11Beacon):
            bssid = pkt[s.Dot11].addr2
            ssid = pkt[s.Dot11Elt].info.decode(errors="replace") if pkt.haslayer(s.Dot11Elt) else ""
            if bssid not in self.aps:
                self.aps[bssid] = ssid
                verdict("INFO", f"AP {ssid or '<hidden>'} ({bssid})")
        elif pkt.haslayer(s.Dot11ProbeReq):
            ssid = pkt[s.Dot11Elt].info.decode(errors="replace") if pkt.haslayer(s.Dot11Elt) else ""
            if ssid:
                verdict("INFO", f"client {pkt[s.Dot11].addr2} probing for '{ssid}'")

    def run(self, iface: str) -> None:
        print(f"[*] harvesting 802.11 airspace on {iface} (monitor mode). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    Harvester().run(args.iface)
    return 0
