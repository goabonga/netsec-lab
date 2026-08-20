# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Discovery-protocol policy simulator (CDP/LLDP): switch-side view.

CDP and LLDP advertise device identity to neighbours in the clear. They belong
on infrastructure links, never on host-facing access ports; a discovery frame
seen on an access port is either recon exposure or a spoofed neighbour. The
defence is simply to disable CDP/LLDP on access ports. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass(frozen=True)
class Neighbour:
    proto: str  # "lldp" | "cdp"
    system_name: str
    ingress_port: str


@dataclass
class DiscoveryPolicy:
    infra_ports: set[str] = field(default_factory=set)

    def observe(self, nb: Neighbour) -> bool:
        """Return True if the advertisement is legitimate, False if a policy violation."""
        if nb.ingress_port in self.infra_ports:
            verdict("FORWARD", f"{nb.proto} neighbour {nb.system_name}", context=nb.ingress_port)
            return True
        verdict(
            "ALERT",
            f"{nb.proto} '{nb.system_name}' on access port -> disable CDP/LLDP here",
            context=nb.ingress_port,
        )
        return False


def demo() -> None:
    """Reference scenario: LLDP on an uplink vs on an access port."""
    policy = DiscoveryPolicy(infra_ports={"Gi0/1"})
    print("--- 1) LLDP on infrastructure uplink Gi0/1 ---")
    policy.observe(Neighbour("lldp", "core-sw-1", "Gi0/1"))
    print("\n--- 2) LLDP/CDP on access port Gi0/3 (recon or spoof) ---")
    policy.observe(Neighbour("lldp", "attacker", "Gi0/3"))
