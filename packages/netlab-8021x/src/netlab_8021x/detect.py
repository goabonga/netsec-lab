# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-8021x: watch for a protected MAC being used.

If a device you have profiled is known to live elsewhere (or be offline), its
MAC appearing on this segment is the signature of a MAB clone.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class MabWatcher:
    def __init__(self, protected: set[str]) -> None:
        self._scapy = load_scapy()
        self.protected = {m.lower() for m in protected}
        self._alerted: set[str] = set()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Ether):
            return
        src = pkt[s.Ether].src.lower()
        if src in self.protected and src not in self._alerted:
            verdict("ALERT", f"protected MAC {src} seen here -> possible MAB clone")
            self._alerted.add(src)

    def run(self, iface: str) -> None:
        print(
            f"[*] watching for cloned MACs on {iface}. protected={self.protected}. Ctrl-C to stop."
        )
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    MabWatcher(set(args.protected)).run(args.iface)
    return 0
