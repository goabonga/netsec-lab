# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""IGMP snooping / join-control simulator: switch-side view.

IGMP snooping forwards a multicast group only to ports that joined it. A forged
join lets an attacker enrol in a group and eavesdrop; restricting which ports
may join sensitive groups (and controlling the querier) contains it. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class SnoopController:
    restricted: dict[str, set[str]] = field(default_factory=dict)  # group -> allowed ports
    members: dict[str, set[str]] = field(default_factory=dict)  # group -> joined ports

    def join(self, group: str, port: str) -> bool:
        """Return True if the join is honoured, False if denied by policy."""
        allowed = self.restricted.get(group)
        if allowed is not None and port not in allowed:
            verdict("DROP", f"join to restricted group {group} from {port} denied", context=port)
            return False
        self.members.setdefault(group, set()).add(port)
        verdict("FORWARD", f"{port} joined {group} (now receives it)", context=port)
        return True


def demo() -> None:
    """Reference scenario: an attacker forges a join to eavesdrop a restricted group."""
    group = "239.1.1.1"
    print("--- 1) unrestricted group: forged join eavesdrops ---")
    SnoopController().join(group, "Gi0/3")
    print("\n--- 2) restricted group: unauthorized join denied ---")
    SnoopController(restricted={group: {"Gi0/2"}}).join(group, "Gi0/3")
