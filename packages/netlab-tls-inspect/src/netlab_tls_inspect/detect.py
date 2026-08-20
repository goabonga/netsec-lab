# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detect side of netlab-tls-inspect: extract SNI from live ClientHello packets."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_tls_inspect.handshake import ClientHello, SniPolicy


def _extract_sni(data: bytes) -> str | None:
    """Best-effort SNI extraction from a TLS ClientHello record.

    Scans for a host_name entry (SNI type 0x00) followed by a 2-byte length and
    a printable dotted host string. Heuristic, not a full TLS parser.
    """
    for i in range(len(data) - 5):
        if data[i] != 0x00:
            continue
        length = int.from_bytes(data[i + 1 : i + 3], "big")
        host = data[i + 3 : i + 3 + length]
        if 0 < length < 255 and b"." in host and all(32 <= b < 127 for b in host):
            return host.decode("ascii")
    return None


class Inspector:
    def __init__(self, policy: SniPolicy) -> None:
        self._scapy = load_scapy()
        self.policy = policy

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.Raw):
            return
        data = bytes(pkt[s.Raw].load)
        if data[:1] == b"\x16":  # TLS handshake record
            sni = _extract_sni(data)
            if sni:
                decision = self.policy.decision(ClientHello(sni))
                icon = "FORWARD" if decision == "allow" else "DROP"
                verdict(icon, f"SNI {sni} = {decision}")

    def run(self, iface: str) -> None:
        print(f"[*] TLS SNI inspector on {iface}. Ctrl-C to stop.")
        self._scapy.sniff(iface=iface, filter="tcp port 443", prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    policy = SniPolicy(allowlist=set(args.allow))
    Inspector(policy).run(args.iface)
    return 0
