# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-lldp-med: flag LLDP-MED network-policy claims."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

_MED_OUI = bytes([0x00, 0x12, 0xBB])


class MedWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Ether) or pkt[s.Ether].type != 0x88CC:
            return
        raw = bytes(pkt[s.Raw].load) if pkt.haslayer(s.Raw) else b""
        if _MED_OUI in raw and b"\x02\x01" in raw:  # network-policy TLV, voice app
            verdict("ALERT", f"LLDP-MED voice-VLAN claim from {pkt[s.Ether].src}")

    def run(self, iface: str) -> None:
        print(f"[*] watching for LLDP-MED voice claims on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    MedWatcher().run(args.iface)
    return 0
