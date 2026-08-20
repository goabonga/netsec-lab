# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""RA Guard simulator: the switch-side defence against rogue IPv6 RAs.

IPv6 hosts autoconfigure their gateway and DNS from Router Advertisements. RA
Guard permits RAs only on ports where the real router lives (trusted); an RA on
any other (access) port is a rogue router and is dropped. Pure logic - safe to
run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass(frozen=True)
class RouterAdvert:
    router_mac: str
    prefix: str
    ingress_port: str


@dataclass
class RaGuard:
    trusted_ports: set[str] = field(default_factory=set)

    def handle(self, ra: RouterAdvert) -> bool:
        """Return True if the RA is accepted, False if dropped as rogue."""
        if ra.ingress_port in self.trusted_ports:
            verdict(
                "FORWARD", f"router {ra.router_mac} prefix {ra.prefix}", context=ra.ingress_port
            )
            return True
        verdict(
            "DROP",
            f"RA from {ra.router_mac} on untrusted port -> ROGUE RA",
            context=ra.ingress_port,
        )
        return False


def demo() -> RaGuard:
    """Reference scenario: legit RA on the uplink, rogue RA on an access port."""
    guard = RaGuard(trusted_ports={"Gi0/1"})
    print("--- 1) real router RA on trusted uplink Gi0/1 ---")
    guard.handle(RouterAdvert("de:ad:be:ef:00:01", "2001:db8:1::/64", "Gi0/1"))
    print("\n--- 2) rogue RA on access port Gi0/3 ---")
    guard.handle(RouterAdvert("66:66:66:66:66:66", "2001:db8:66::/64", "Gi0/3"))
    return guard
