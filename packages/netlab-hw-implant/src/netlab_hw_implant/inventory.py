# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Asset-inventory / NAC simulator: catching a rogue hardware implant.

A dropped implant or BadUSB network device appears on the wire as a new MAC.
802.1X port-based NAC and an asset inventory reject any device whose MAC is not
sanctioned. Pure logic - safe to run anywhere (the implant itself is physical).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class AssetInventory:
    known: set[str] = field(default_factory=set)  # sanctioned device MACs

    def observe(self, mac: str) -> bool:
        """Return True if the device is authorized, False if it is a rogue implant."""
        if mac in self.known:
            verdict("FORWARD", f"authorized device {mac}")
            return True
        verdict("ALERT", f"unknown device {mac} -> ROGUE IMPLANT (NAC blocks)")
        return False


def demo() -> None:
    """Reference scenario: a sanctioned host vs a dropped implant."""
    inv = AssetInventory(known={"aa:bb:cc:00:00:10"})
    print("--- 1) sanctioned corporate host ---")
    inv.observe("aa:bb:cc:00:00:10")
    print("\n--- 2) rogue implant / BadUSB device ---")
    inv.observe("66:66:66:66:66:66")
