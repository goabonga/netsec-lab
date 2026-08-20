# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Dynamic ARP Inspection simulator: the switch-side defence, dependency-free.

Validates ARP packets on untrusted ports against the DHCP snooping binding
table (reused from netlab-core): an ARP whose sender MAC/IP pair was never
learned is a spoof and gets dropped. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netlab_core import Binding, BindingTable, verdict


class ArpOp(Enum):
    REQUEST = "request"
    REPLY = "reply"


@dataclass(frozen=True)
class ArpPacket:
    op: ArpOp
    sender_mac: str
    sender_ip: str
    ingress_port: str


@dataclass
class ArpInspector:
    """DAI: drop ARP on untrusted ports that contradicts the binding table."""

    bindings: BindingTable
    trusted_ports: set[str] = field(default_factory=set)

    def handle(self, pkt: ArpPacket) -> bool:
        """Return True if the ARP is forwarded, False if dropped as a spoof."""
        if pkt.ingress_port in self.trusted_ports:
            verdict("FORWARD", "trusted port", context=pkt.op.value)
            return True
        if self.bindings.is_valid(pkt.sender_mac, pkt.sender_ip):
            verdict("FORWARD", f"{pkt.sender_mac} -> {pkt.sender_ip}", context=pkt.op.value)
            return True
        verdict(
            "DROP",
            f"{pkt.sender_mac} claims {pkt.sender_ip} (no binding) -> ARP SPOOF",
            context=pkt.op.value,
        )
        return False


def demo() -> ArpInspector:
    """Reference scenario: a legit ARP passes, a gateway-impersonation is dropped."""
    bindings = BindingTable()
    bindings.learn(Binding(mac="aa:bb:cc:00:00:11", ip="192.168.1.50", vlan=10, port="Gi0/2"))
    bindings.learn(Binding(mac="de:ad:be:ef:00:01", ip="192.168.1.1", vlan=10, port="Gi0/1"))
    dai = ArpInspector(bindings=bindings, trusted_ports={"Gi0/1"})
    print("--- 1) legitimate host ARP (matches its binding) ---")
    dai.handle(ArpPacket(ArpOp.REPLY, "aa:bb:cc:00:00:11", "192.168.1.50", "Gi0/2"))
    print("\n--- 2) attacker impersonating the gateway (gratuitous ARP) ---")
    dai.handle(ArpPacket(ArpOp.REPLY, "66:66:66:66:66:66", "192.168.1.1", "Gi0/3"))
    return dai
