# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-ntp: flag NTP replies from unexpected servers."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class NtpWatcher:
    def __init__(self, allow: set[str]) -> None:
        self._scapy = load_scapy()
        self.allow = allow

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.NTP) or not pkt.haslayer(s.IP):
            return
        src = pkt[s.IP].src
        if src not in self.allow:
            verdict("ALERT", f"NTP reply from {src} not in allowlist -> possible time-shift MITM")

    def run(self, iface: str) -> None:
        print(f"[*] watching NTP on {iface}. allow={self.allow or '(empty)'}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp port 123", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    NtpWatcher(set(args.allow)).run(args.iface)
    return 0
