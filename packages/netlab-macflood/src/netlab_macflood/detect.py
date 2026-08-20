# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-macflood: spot CAM-table flooding.

Counts distinct source MACs seen on the segment; an abnormal number in a short
window is the signature of a macof-style flood. The host-side view of what
port-security enforces on the switch.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class CamFloodWatcher:
    def __init__(self, threshold: int) -> None:
        self._scapy = load_scapy()
        self.threshold = threshold
        self.macs: set[str] = set()
        self._alerted = False

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Ether):
            return
        self.macs.add(pkt[s.Ether].src)
        if len(self.macs) > self.threshold and not self._alerted:
            verdict("ALERT", f"{len(self.macs)} distinct source MACs -> CAM FLOODING")
            self._alerted = True

    def run(self, iface: str) -> None:
        print(f"[*] watching source MACs on {iface} (threshold {self.threshold}). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    CamFloodWatcher(args.threshold).run(args.iface)
    return 0
