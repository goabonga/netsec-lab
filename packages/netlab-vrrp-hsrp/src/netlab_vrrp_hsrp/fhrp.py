# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""FHRP (VRRP/HSRP) master-election simulator: gateway-redundancy view.

The router advertising the highest priority owns the virtual gateway IP/MAC. An
attacker advertising a higher priority becomes master and receives the segment's
outbound traffic. FHRP authentication rejects the forged advertisement. Pure
logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class VirtualRouter:
    master_priority: int = 100
    require_auth: bool = False

    def advertise(self, priority: int, authenticated: bool = False) -> bool:
        """Return True if this advertiser becomes master, False otherwise."""
        if self.require_auth and not authenticated:
            verdict("DROP", f"unauthenticated advertisement (priority {priority}) rejected")
            return False
        if priority > self.master_priority:
            self.master_priority = priority
            verdict("ALERT", f"priority {priority} -> new MASTER (gateway takeover)")
            return True
        verdict("FORWARD", f"priority {priority} <= master, ignored")
        return False


def demo() -> None:
    """Reference scenario: an attacker preempts the master, then an authenticated group."""
    print("--- 1) group without authentication ---")
    VirtualRouter(master_priority=100, require_auth=False).advertise(255)
    print("\n--- 2) group with FHRP authentication ---")
    VirtualRouter(master_priority=100, require_auth=True).advertise(255, authenticated=False)
