# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-ids-evasion: flag suspiciously low-TTL segments."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class TtlWatcher:
    def __init__(self, min_ttl: int) -> None:
        self._scapy = load_scapy()
        self.min_ttl = min_ttl

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.IP) and pkt.haslayer(s.TCP) and pkt[s.IP].ttl < self.min_ttl:
            verdict(
                "ALERT", f"segment ttl {pkt[s.IP].ttl} < {self.min_ttl} -> possible TTL insertion"
            )

    def run(self, iface: str) -> None:
        print(f"[*] watching for low-TTL segments on {iface} (min {self.min_ttl}).")
        self._scapy.sniff(iface=iface, filter="tcp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    TtlWatcher(args.min_ttl).run(args.iface)
    return 0
