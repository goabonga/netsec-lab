# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-ipspoof: flag packets sourced outside the local prefix."""

from __future__ import annotations

import argparse
import ipaddress
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class SpoofWatcher:
    def __init__(self, prefix: str) -> None:
        self._scapy = load_scapy()
        self.net = ipaddress.ip_network(prefix)

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.IP):
            return
        src = pkt[s.IP].src
        if ipaddress.ip_address(src) not in self.net:
            verdict("ALERT", f"packet sourced {src} outside {self.net} -> SPOOFED")

    def run(self, iface: str) -> None:
        print(f"[*] watching for off-prefix sources on {iface} ({self.net}). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="ip", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    SpoofWatcher(args.prefix).run(args.iface)
    return 0
