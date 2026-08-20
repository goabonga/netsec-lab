# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-tap: passively capture traffic off the wire. LAB ONLY.

Sniffs the segment - the software half of a physical tap. A real copper/fibre tap
needs a TAP or optical coupler and physical access; on a link you own, encrypting
it (MACsec/IPsec, see exposure.py) makes the capture worthless.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class Tap:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.count = 0

    def _handle(self, pkt: Any) -> None:
        self.count += 1
        if self.count % 100 == 0:
            verdict("ALERT", f"captured {self.count} frames off the tap")

    def run(self, iface: str) -> None:
        print(f"[*] passively capturing on {iface} (physical tap needs a coupler). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    Tap().run(args.iface)
    return 0
