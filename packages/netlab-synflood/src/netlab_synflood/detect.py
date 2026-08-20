# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-synflood: flag a SYN flood (many SYNs, few ACKs)."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class SynFloodWatcher:
    def __init__(self, threshold: int) -> None:
        self._scapy = load_scapy()
        self.threshold = threshold
        self.syns = 0
        self.acks = 0
        self._alerted = False

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.TCP):
            return
        flags = pkt[s.TCP].flags
        if flags & 0x02 and not flags & 0x10:  # SYN without ACK
            self.syns += 1
        elif flags & 0x10:
            self.acks += 1
        if self.syns - self.acks > self.threshold and not self._alerted:
            verdict("ALERT", f"{self.syns} SYN / {self.acks} ACK -> SYN FLOOD")
            self._alerted = True

    def run(self, iface: str) -> None:
        print(f"[*] watching for SYN floods on {iface} (threshold {self.threshold}).")
        self._scapy.sniff(iface=iface, filter="tcp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    SynFloodWatcher(args.threshold).run(args.iface)
    return 0
