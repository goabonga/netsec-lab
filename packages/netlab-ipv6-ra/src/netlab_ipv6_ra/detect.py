# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-ipv6-ra: spot rogue Router Advertisements."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class RaWatcher:
    def __init__(self, allow: set[str]) -> None:
        self._scapy = load_scapy()
        self.allow = allow
        self.seen: set[str] = set()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.ICMPv6ND_RA):
            return
        src = pkt[s.IPv6].src if pkt.haslayer(s.IPv6) else "?"
        if src in self.seen:
            return
        self.seen.add(src)
        if src in self.allow:
            verdict("FORWARD", f"legit router {src}")
        else:
            verdict("ALERT", f"RA from {src} not in allowlist -> ROGUE RA")
        if len(self.seen) > 1:
            verdict("ALERT", f"{len(self.seen)} routers advertising: {', '.join(self.seen)}")

    def run(self, iface: str) -> None:
        print(f"[*] watching IPv6 RAs on {iface}. allow={self.allow or '(empty)'}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="icmp6", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    RaWatcher(set(args.allow)).run(args.iface)
    return 0
