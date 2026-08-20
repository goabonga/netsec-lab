# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-wifi-deauth: flag a deauthentication flood."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class DeauthWatcher:
    def __init__(self, threshold: int) -> None:
        self._scapy = load_scapy()
        self.threshold = threshold
        self.count = 0
        self._alerted = False

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.Dot11Deauth):
            self.count += 1
            if self.count > self.threshold and not self._alerted:
                verdict("ALERT", f"{self.count} deauth frames -> DEAUTH FLOOD")
                self._alerted = True

    def run(self, iface: str) -> None:
        print(f"[*] watching for deauth floods on {iface} (threshold {self.threshold}).")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    DeauthWatcher(args.threshold).run(args.iface)
    return 0
