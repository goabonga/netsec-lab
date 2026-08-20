# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detect side of netlab-netflow: build flows from live traffic and flag fan-out."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_netflow.flow import FlowTable


class Exporter:
    def __init__(self, threshold: int) -> None:
        self._scapy = load_scapy()
        self.table = FlowTable()
        self.threshold = threshold
        self._flagged: set[str] = set()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not (pkt.haslayer(s.IP) and pkt.haslayer(s.TCP)):
            return
        self.table.add("tcp", pkt[s.IP].src, pkt[s.IP].dst, int(pkt[s.TCP].dport), len(pkt))
        for scanner in self.table.scanners(self.threshold):
            if scanner not in self._flagged:
                self._flagged.add(scanner)
                verdict("ALERT", f"{scanner} reached {self.table.fanout(scanner)} hosts -> scan")

    def run(self, iface: str) -> None:
        print(f"[*] flow exporter on {iface} (fan-out threshold {self.threshold}). Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="tcp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    Exporter(args.threshold).run(args.iface)
    return 0
