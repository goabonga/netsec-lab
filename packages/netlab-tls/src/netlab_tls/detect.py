# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-tls: flag plaintext HTTP to a should-be-HTTPS host."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class StripWatcher:
    def __init__(self, https_hosts: set[str]) -> None:
        self._scapy = load_scapy()
        self.https_hosts = https_hosts

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.TCP) and pkt[s.TCP].dport == 80 and pkt.haslayer(s.IP):
            if pkt[s.IP].dst in self.https_hosts:
                verdict("ALERT", f"plaintext HTTP to {pkt[s.IP].dst} -> SSL STRIP")

    def run(self, iface: str) -> None:
        print(f"[*] watching for HTTP to HTTPS-only hosts on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="tcp port 80", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    StripWatcher(set(args.https_hosts)).run(args.iface)
    return 0
