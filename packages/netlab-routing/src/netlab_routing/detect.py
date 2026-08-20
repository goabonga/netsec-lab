# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-routing: flag RIP updates from unexpected sources."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class RipWatcher:
    def __init__(self, allow: set[str]) -> None:
        self._scapy = load_scapy()
        self.allow = allow

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.RIP):
            return
        src = pkt[s.IP].src if pkt.haslayer(s.IP) else "?"
        if src not in self.allow:
            verdict("ALERT", f"RIP update from {src} not in allowlist -> ROUTE INJECTION")

    def run(self, iface: str) -> None:
        print(f"[*] watching RIP on {iface}. allow={self.allow or '(empty)'}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp port 520", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    RipWatcher(set(args.allow)).run(args.iface)
    return 0
