# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detect side of netlab-firewall: evaluate live traffic against the ACL."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_firewall.acl import Firewall, Packet, Rule

DEFAULT_FW = Firewall(
    rules=[Rule("allow", proto="tcp", dport=443), Rule("allow", proto="tcp", dport=80)],
    default="deny",
    stateful=True,
)


class Inspector:
    def __init__(self, fw: Firewall) -> None:
        self._scapy = load_scapy()
        self.fw = fw

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not (pkt.haslayer(s.IP) and pkt.haslayer(s.TCP)):
            return
        tcp = pkt[s.TCP]
        established = bool(tcp.flags & 0x10) and not bool(tcp.flags & 0x02)  # ACK set, SYN clear
        p = Packet("tcp", pkt[s.IP].src, pkt[s.IP].dst, int(tcp.dport), established=established)
        decision = self.fw.evaluate(p)
        if decision == "deny":
            verdict("DROP", f"{p.src} -> {p.dst}:{p.dport} denied by policy")

    def run(self, iface: str) -> None:
        print(f"[*] firewall inspector on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="tcp", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    Inspector(DEFAULT_FW).run(args.iface)
    return 0
