# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-dhcp: spot a rogue DHCP server on the segment.

The host-side counterpart of DHCP snooping: it cannot drop the packet (it is
not the switch) but it detects and alerts on any server not in the allowlist,
and on more than one DHCP server answering on the segment.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

_MSG = {2: "OFFER", 5: "ACK"}


class Detector:
    def __init__(self, allow: set[str]) -> None:
        self.allow = allow
        self.seen: dict[str, str] = {}  # server_id -> src_mac
        self._scapy = load_scapy()

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.DHCP):
            return
        opts = {o[0]: o[1] for o in pkt[s.DHCP].options if isinstance(o, tuple)}
        mtype = opts.get("message-type")
        if mtype not in _MSG:
            return
        server_id = opts.get("server_id") or (pkt[s.IP].src if pkt.haslayer(s.IP) else "?")
        if server_id in self.seen:
            return
        src_mac = pkt[s.Ether].src if pkt.haslayer(s.Ether) else "?"
        self.seen[server_id] = src_mac
        if server_id in self.allow:
            verdict("FORWARD", f"legit server {server_id}", context=_MSG[mtype])
        else:
            verdict(
                "ALERT",
                f"ROGUE DHCP {server_id} (mac {src_mac}) router={opts.get('router')}",
                context=_MSG[mtype],
            )
        if len(self.seen) > 1:
            verdict(
                "ALERT",
                f"{len(self.seen)} distinct DHCP servers: "
                f"{', '.join(self.seen)} -> segment likely compromised",
            )

    def run(self, iface: str) -> None:
        print(f"[*] watching DHCP on {iface}. allowlist={self.allow or '(empty)'}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="udp and port 68", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    Detector(allow=set(args.allow)).run(args.iface)
    return 0
