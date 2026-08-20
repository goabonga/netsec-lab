# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""IGP route-injection simulator (RIP/OSPF): router-side view.

An interior gateway protocol installs routes from neighbour advertisements.
Without neighbour authentication, an attacker injects routes to blackhole or
reroute traffic; MD5/SHA neighbour auth rejects the forged update. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class Router:
    require_auth: bool = False
    table: dict[str, str] = field(default_factory=dict)  # prefix -> next-hop

    def inject(self, prefix: str, next_hop: str, authenticated: bool = False) -> bool:
        """Return True if the route was installed, False if the update was rejected."""
        if self.require_auth and not authenticated:
            verdict("DROP", f"unauthenticated update for {prefix} rejected", context=next_hop)
            return False
        override = prefix in self.table
        self.table[prefix] = next_hop
        verdict(
            "ALERT" if override else "LEARN",
            f"{prefix} -> {next_hop}"
            + (" (overrides existing -> reroute/blackhole)" if override else ""),
        )
        return True


def demo() -> None:
    """Reference scenario: a forged route override vs an authenticated router."""
    print("--- 1) router without neighbour auth ---")
    r = Router(require_auth=False)
    r.table["10.0.0.0/8"] = "192.168.1.1"  # legit route
    r.inject("10.0.0.0/8", "192.168.1.66")  # attacker reroutes it
    print("\n--- 2) router with neighbour authentication ---")
    Router(require_auth=True).inject("10.0.0.0/8", "192.168.1.66", authenticated=False)
