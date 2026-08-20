# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-macsec: flag cleartext frames on a protected link.

MACsec frames carry EtherType 0x88e5. A non-MACsec frame on a link that should
be protected means MACsec is not actually enabled - a cleartext exposure.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

_MACSEC_ETHERTYPE = 0x88E5


class MacsecWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self._alerted = False

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Ether):
            return
        if pkt[s.Ether].type != _MACSEC_ETHERTYPE and not self._alerted:
            verdict("ALERT", "cleartext frame on a link expected to be MACsec-protected")
            self._alerted = True

    def run(self, iface: str) -> None:
        print(f"[*] checking MACsec posture on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    MacsecWatcher().run(args.iface)
    return 0
