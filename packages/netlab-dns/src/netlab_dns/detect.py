# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-dns: flag racing / duplicate DNS answers."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class PoisonWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.answers: dict[int, int] = {}  # txid -> reply count

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.DNS) or pkt[s.DNS].qr != 1:
            return
        txid = int(pkt[s.DNS].id)
        self.answers[txid] = self.answers.get(txid, 0) + 1
        if self.answers[txid] > 1:
            verdict("ALERT", f"multiple answers for txid {txid:#06x} -> CACHE-POISONING RACE")

    def run(self, iface: str) -> None:
        print(f"[*] watching for DNS answer races on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp port 53", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    PoisonWatcher().run(args.iface)
    return 0
