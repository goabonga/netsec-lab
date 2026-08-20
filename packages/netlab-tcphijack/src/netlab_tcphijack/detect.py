# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-tcphijack: flag injected RSTs / mid-stream resets."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class RstWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.TCP) and pkt[s.TCP].flags & 0x04:  # RST
            ip = pkt[s.IP]
            verdict(
                "ALERT",
                f"RST {ip.src}:{pkt[s.TCP].sport} -> {ip.dst}:{pkt[s.TCP].dport} (possible hijack)",
            )

    def run(self, iface: str) -> None:
        print(f"[*] watching for RST injections on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(
            iface=iface, filter="tcp[tcpflags] & tcp-rst != 0", prn=self._handle, store=0
        )


def run(args: argparse.Namespace) -> int:
    RstWatcher().run(args.iface)
    return 0
