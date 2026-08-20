# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-icmp: flag ICMP redirects on the segment."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class RedirectWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.ICMP) and pkt[s.ICMP].type == 5:
            verdict("ALERT", f"ICMP redirect from {pkt[s.IP].src} -> possible MITM")

    def run(self, iface: str) -> None:
        print(f"[*] watching for ICMP redirects on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="icmp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    RedirectWatcher().run(args.iface)
    return 0
