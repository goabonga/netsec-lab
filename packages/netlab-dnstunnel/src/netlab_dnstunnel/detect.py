# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-dnstunnel: flag high-entropy DNS labels."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_dnstunnel.tunnel import label_entropy


class TunnelWatcher:
    def __init__(self, entropy_threshold: float) -> None:
        self._scapy = load_scapy()
        self.threshold = entropy_threshold

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.DNSQR):
            return
        qname = pkt[s.DNSQR].qname.decode(errors="replace")
        label = qname.split(".", 1)[0]
        if len(label) > 20 and label_entropy(label) > self.threshold:
            verdict("ALERT", f"high-entropy label {label[:16]}... -> DNS TUNNEL")

    def run(self, iface: str) -> None:
        print(f"[*] watching for DNS tunnelling on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp port 53", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    TunnelWatcher(args.entropy).run(args.iface)
    return 0
