# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detect side of netlab-macsec-monitor: watch a link for loss of MACsec."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

MACSEC_ETHERTYPE = 0x88E5


class Monitor:
    def __init__(self, port: str) -> None:
        self._scapy = load_scapy()
        self.port = port

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.Ether) and pkt[s.Ether].type != MACSEC_ETHERTYPE:
            verdict("ALERT", f"{self.port}: cleartext frame on a protected link -> MACsec down")

    def run(self, iface: str) -> None:
        print(f"[*] MACsec monitor on {iface} ({self.port}). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0, count=10)


def run(args: argparse.Namespace) -> int:
    Monitor(args.iface).run(args.iface)
    return 0
