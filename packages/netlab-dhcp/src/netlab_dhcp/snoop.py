# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""DHCP snooping simulator: the switch-side logic, dependency-free.

Models trusted/untrusted ports, the binding table, rogue-server drop and
per-port DISCOVER rate-limiting. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netlab_core import Binding, BindingTable, verdict


class DhcpType(Enum):
    DISCOVER = "DISCOVER"  # client -> server
    OFFER = "OFFER"  # server -> client
    REQUEST = "REQUEST"  # client -> server
    ACK = "ACK"  # server -> client


SERVER_MESSAGES = {DhcpType.OFFER, DhcpType.ACK}


@dataclass(frozen=True)
class DhcpPacket:
    kind: DhcpType
    src_mac: str
    ingress_port: str
    vlan: int = 10
    your_ip: str | None = None  # yiaddr (offered/granted IP)
    client_mac: str | None = None  # chaddr (the client the lease is for)


@dataclass
class SnoopingSwitch:
    """A switch enforcing DHCP snooping on a set of trusted ports."""

    trusted_ports: set[str]
    max_discover_per_port: int = 3
    bindings: BindingTable = field(default_factory=BindingTable)
    _discover_count: dict[str, int] = field(default_factory=dict)

    def handle(self, pkt: DhcpPacket) -> bool:
        """Return True if the packet is forwarded, False if dropped."""
        trusted = pkt.ingress_port in self.trusted_ports

        # Rule 1: a server message on an untrusted port is a rogue server.
        if pkt.kind in SERVER_MESSAGES and not trusted:
            verdict(
                "DROP",
                "server message on UNTRUSTED port -> ROGUE DHCP",
                context=f"{pkt.kind.value} {pkt.ingress_port}",
            )
            return False

        # Rule 2: rate-limit DISCOVER on untrusted ports (anti-starvation).
        if pkt.kind is DhcpType.DISCOVER and not trusted:
            n = self._discover_count.get(pkt.ingress_port, 0) + 1
            self._discover_count[pkt.ingress_port] = n
            if n > self.max_discover_per_port:
                verdict(
                    "DROP",
                    f"DISCOVER rate-limit exceeded ({n}) -> STARVATION",
                    context=pkt.ingress_port,
                )
                return False

        # Rule 3: learn the lease from a legitimate ACK (trusted port).
        if pkt.kind is DhcpType.ACK and trusted and pkt.your_ip and pkt.client_mac:
            self.bindings.learn(
                Binding(
                    mac=pkt.client_mac,
                    ip=pkt.your_ip,
                    vlan=pkt.vlan,
                    port=pkt.ingress_port,
                    lease=86400,
                )
            )
            verdict("LEARN", f"{pkt.client_mac} -> {pkt.your_ip}", context=pkt.kind.value)

        verdict("FORWARD", "ok", context=f"{pkt.kind.value} {pkt.ingress_port}")
        return True


def demo() -> SnoopingSwitch:
    """Run the reference scenario: legit DORA, rogue server, starvation."""
    sw = SnoopingSwitch(trusted_ports={"Gi0/1"})
    print("--- 1) legitimate DORA (client Gi0/2, server Gi0/1) ---")
    sw.handle(DhcpPacket(DhcpType.DISCOVER, "aa:bb:cc:00:00:11", "Gi0/2"))
    sw.handle(DhcpPacket(DhcpType.OFFER, "de:ad:be:ef:00:01", "Gi0/1", your_ip="192.168.1.50"))
    sw.handle(DhcpPacket(DhcpType.REQUEST, "aa:bb:cc:00:00:11", "Gi0/2"))
    sw.handle(
        DhcpPacket(
            DhcpType.ACK,
            "de:ad:be:ef:00:01",
            "Gi0/1",
            your_ip="192.168.1.50",
            client_mac="aa:bb:cc:00:00:11",
        )
    )
    print("\n--- 2) rogue server on untrusted Gi0/3 ---")
    sw.handle(DhcpPacket(DhcpType.OFFER, "66:66:66:66:66:66", "Gi0/3", your_ip="192.168.1.66"))
    print("\n--- 3) DHCP starvation on Gi0/3 ---")
    for i in range(6):
        sw.handle(DhcpPacket(DhcpType.DISCOVER, f"12:34:56:00:00:{i:02x}", "Gi0/3"))
    return sw
