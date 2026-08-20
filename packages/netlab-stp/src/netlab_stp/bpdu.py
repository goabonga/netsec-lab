# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""STP root-election simulator with BPDU Guard: switch-side defence.

A bridge believes the lowest priority it has heard is the root. A superior
(lower) BPDU makes the sender root and reconverges the topology. BPDU Guard
err-disables an access/edge port the moment it receives any BPDU, since a host
port should never speak STP. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class Bridge:
    priority: int = 32768
    edge_ports: set[str] = field(default_factory=set)
    root_priority: int = field(init=False)

    def __post_init__(self) -> None:
        self.root_priority = self.priority

    def receive_bpdu(self, sender_root_priority: int, ingress_port: str) -> bool:
        """Return True if the BPDU is accepted, False if the port is guarded."""
        if ingress_port in self.edge_ports:
            verdict("DROP", "BPDU on edge port -> BPDU Guard err-disable", context=ingress_port)
            return False
        if sender_root_priority < self.root_priority:
            self.root_priority = sender_root_priority
            verdict(
                "ALERT",
                f"superior root {sender_root_priority} -> ROOT TAKEOVER (reconverge)",
                context=ingress_port,
            )
            return True
        verdict(
            "FORWARD", f"inferior/equal BPDU ({sender_root_priority}) ignored", context=ingress_port
        )
        return True


def demo() -> Bridge:
    """Reference scenario: superior BPDU on a trunk, then a BPDU on an edge port."""
    bridge = Bridge(priority=32768, edge_ports={"Gi0/2"})
    print("--- 1) attacker sends a superior BPDU on trunk Gi0/1 ---")
    bridge.receive_bpdu(sender_root_priority=0, ingress_port="Gi0/1")
    print("\n--- 2) any BPDU arriving on access port Gi0/2 ---")
    bridge.receive_bpdu(sender_root_priority=0, ingress_port="Gi0/2")
    return bridge
