# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-quic: classify QUIC packets on the wire."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_quic.header import classify


class QuicWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.UDP) and pkt.haslayer(s.Raw):
            data = bytes(pkt[s.Raw].load)
            if data:
                verdict("INFO", classify(data[0]))

    def run(self, iface: str) -> None:
        print(f"[*] classifying QUIC on {iface} (UDP 443). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp port 443", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    QuicWatcher().run(args.iface)
    return 0
