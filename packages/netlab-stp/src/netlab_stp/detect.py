# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-stp: spot an STP root takeover.

Tracks the best (lowest) root priority heard; a sudden superior root - or any
BPDU seen on a host-facing port - signals a spanning-tree attack.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class BpduWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.best_root: int | None = None

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.STP):
            return
        root = int(pkt[s.STP].rootid)
        if self.best_root is None:
            self.best_root = root
            verdict("LEARN", f"root priority {root}")
        elif root < self.best_root:
            verdict("ALERT", f"new superior root {root} < {self.best_root} -> ROOT TAKEOVER")
            self.best_root = root

    def run(self, iface: str) -> None:
        print(f"[*] watching BPDUs on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="stp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    BpduWatcher().run(args.iface)
    return 0
