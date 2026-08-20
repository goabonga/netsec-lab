# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-wpa-crack: flag handshake-capture attempts."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class HandshakeWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.deauths = 0

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.Dot11Deauth):
            self.deauths += 1
        elif pkt.haslayer(s.EAPOL) and self.deauths:
            verdict("ALERT", "EAPOL handshake after deauth -> capture attempt")

    def run(self, iface: str) -> None:
        print(f"[*] watching for deauth-assisted handshake capture on {iface}.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    HandshakeWatcher().run(args.iface)
    return 0
