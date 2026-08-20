# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-mdns-llmnr: flag LLMNR/mDNS responses on the segment."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class ResponderWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.LLMNRResponse) and pkt.haslayer(s.IP):
            verdict("ALERT", f"LLMNR response from {pkt[s.IP].src} -> possible name poisoning")

    def run(self, iface: str) -> None:
        print(f"[*] watching for LLMNR/mDNS responses on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(
            iface=iface, filter="udp port 5355 or udp port 5353", prn=self._handle, store=0
        )


def run(args: argparse.Namespace) -> int:
    ResponderWatcher().run(args.iface)
    return 0
