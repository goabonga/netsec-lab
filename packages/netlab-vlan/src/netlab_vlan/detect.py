# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-vlan: spot 802.1Q double-tagged frames."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class DoubleTagWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Dot1Q):
            return
        # count stacked Dot1Q layers
        layer, depth = pkt, 0
        while layer is not None and layer.haslayer(s.Dot1Q):
            depth += 1
            layer = layer[s.Dot1Q].payload
        if depth >= 2:
            verdict("ALERT", f"double-tagged frame ({depth} tags) -> VLAN HOPPING")

    def run(self, iface: str) -> None:
        print(f"[*] watching for double-tagged frames on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    DoubleTagWatcher().run(args.iface)
    return 0
