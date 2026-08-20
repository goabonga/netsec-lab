# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-snmp: flag community brute-forcing."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class SnmpWatcher:
    def __init__(self, threshold: int) -> None:
        self._scapy = load_scapy()
        self.threshold = threshold
        self.communities: set[bytes] = set()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.SNMP):
            return
        self.communities.add(bytes(pkt[s.SNMP].community))
        if len(self.communities) > self.threshold:
            verdict("ALERT", f"{len(self.communities)} distinct communities tried -> SNMP BRUTE")

    def run(self, iface: str) -> None:
        print(f"[*] watching SNMP on {iface} (threshold {self.threshold}). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp port 161", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    SnmpWatcher(args.threshold).run(args.iface)
    return 0
