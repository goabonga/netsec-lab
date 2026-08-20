# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-frag: flag overlapping IP fragments."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class FragWatcher:
    def __init__(self) -> None:
        self._scapy = load_scapy()
        self.seen: dict[int, list[tuple[int, int]]] = {}  # ip id -> [(start, end)]

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.IP):
            return
        ip = pkt[s.IP]
        if ip.frag == 0 and not (int(ip.flags) & 1):
            return  # not fragmented
        start = ip.frag * 8
        end = start + len(bytes(ip.payload))
        ranges = self.seen.setdefault(ip.id, [])
        for s0, e0 in ranges:
            if start < e0 and s0 < end:
                verdict("ALERT", f"overlapping fragments (id {ip.id:#x}) -> IDS EVASION")
                break
        ranges.append((start, end))

    def run(self, iface: str) -> None:
        print(f"[*] watching for overlapping fragments on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="ip", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    FragWatcher().run(args.iface)
    return 0
