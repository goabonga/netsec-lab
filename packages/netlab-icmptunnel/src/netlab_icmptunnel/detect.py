# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-icmptunnel: flag oversized / data-carrying echo payloads."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class EchoWatcher:
    def __init__(self, max_payload: int) -> None:
        self._scapy = load_scapy()
        self.max_payload = max_payload

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.ICMP) or pkt[s.ICMP].type not in (0, 8):
            return
        payload = bytes(pkt[s.ICMP].payload)
        if len(payload) > self.max_payload:
            verdict(
                "ALERT",
                f"echo payload {len(payload)}B > {self.max_payload} -> possible ICMP TUNNEL",
            )

    def run(self, iface: str) -> None:
        print(f"[*] watching ICMP echo payloads on {iface} (max {self.max_payload}B).")
        self._scapy.sniff(iface=iface, filter="icmp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    EchoWatcher(args.max_payload).run(args.iface)
    return 0
