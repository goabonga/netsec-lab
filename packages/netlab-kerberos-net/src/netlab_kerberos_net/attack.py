# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-kerberos-net: capture Kerberos exchanges on the wire. LAB ONLY.

Sniffs AS/TGS traffic (port 88) and reports the encryption type - legacy enctypes
yield offline-crackable material. Network dimension only, no application ticket
exploitation. Strong enctypes and PKINIT (see enctype.py) are the fix.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class Sniffer:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.count = 0

    def _handle(self, pkt: Any) -> None:
        self.count += 1
        verdict("INFO", f"captured Kerberos message #{self.count} (inspect enctype offline)")

    def run(self, iface: str) -> None:
        print(f"[*] capturing Kerberos (port 88) on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(
            iface=iface, filter="tcp port 88 or udp port 88", prn=self._handle, store=0
        )


def run(args: argparse.Namespace) -> int:
    Sniffer().run(args.iface)
    return 0
