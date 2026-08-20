# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-amplif: flag large unsolicited UDP replies to a victim."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class AmplifWatcher:
    def __init__(self, victim: str, min_size: int) -> None:
        self._scapy = load_scapy()
        self.victim = victim
        self.min_size = min_size

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not (pkt.haslayer(s.IP) and pkt.haslayer(s.UDP)):
            return
        if pkt[s.IP].dst == self.victim and len(pkt) >= self.min_size:
            verdict(
                "ALERT",
                f"large UDP reply ({len(pkt)}B) to {self.victim} -> reflection/amplification",
            )

    def run(self, iface: str) -> None:
        print(f"[*] watching for reflected replies to {self.victim} on {iface}.")
        self._scapy.sniff(iface=iface, filter="udp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    AmplifWatcher(args.victim, args.min_size).run(args.iface)
    return 0
