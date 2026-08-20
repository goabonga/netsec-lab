# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-covert: flag ID fields that decode to printable ASCII."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class CovertWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.IP):
            return
        two = int(pkt[s.IP].id).to_bytes(2, "big")
        if all(0x20 <= b < 0x7F for b in two):
            verdict("ALERT", f"IP ID decodes to printable {two!r} -> possible covert channel")

    def run(self, iface: str) -> None:
        print(f"[*] watching IP ID entropy on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="ip", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    CovertWatcher().run(args.iface)
    return 0
