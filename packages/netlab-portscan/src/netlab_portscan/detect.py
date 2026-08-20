# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-portscan: flag a host sweeping many ports."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core.sniffing import load_scapy

from netlab_portscan.scandet import ScanDetector


class ScanWatcher:
    def __init__(self, threshold: int) -> None:
        self._scapy = load_scapy()
        self.det = ScanDetector(threshold=threshold)

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.TCP) and pkt.haslayer(s.IP):
            self.det.observe(pkt[s.IP].src, int(pkt[s.TCP].dport))

    def run(self, iface: str) -> None:
        print(f"[*] watching for port scans on {iface} (threshold {self.det.threshold}).")
        self._scapy.sniff(iface=iface, filter="tcp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    ScanWatcher(args.threshold).run(args.iface)
    return 0
