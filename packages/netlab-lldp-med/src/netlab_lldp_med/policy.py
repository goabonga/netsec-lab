# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""LLDP-MED voice-VLAN policy simulator: switch-side view.

With LLDP-MED, the switch tells an IP phone which voice VLAN to tag itself with.
A switch that trusts a device's *claimed* voice VLAN lets a rogue device pick
any VLAN (segmentation bypass). Enforcing a statically configured voice VLAN per
port removes the abuse. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class VoicePolicy:
    configured_voice: dict[str, int] = field(default_factory=dict)  # port -> voice VLAN
    honor_lldp_med: bool = True

    def assign(self, port: str, claimed_vlan: int) -> int | None:
        """Return the voice VLAN the device is placed in (None if the port has none)."""
        static = self.configured_voice.get(port)
        if static is None:
            verdict("DROP", "no voice VLAN configured on this port", context=port)
            return None
        if self.honor_lldp_med and claimed_vlan != static:
            verdict(
                "ALERT", f"honoured claimed voice VLAN {claimed_vlan} -> VLAN ABUSE", context=port
            )
            return claimed_vlan
        verdict("FORWARD", f"static voice VLAN {static}", context=port)
        return static


def demo() -> None:
    """Reference scenario: a rogue device claims a voice VLAN it should not get."""
    print("--- 1) switch trusts LLDP-MED (device claims VLAN 200) ---")
    VoicePolicy(configured_voice={"Gi0/2": 100}, honor_lldp_med=True).assign("Gi0/2", 200)
    print("\n--- 2) switch enforces a static voice VLAN ---")
    VoicePolicy(configured_voice={"Gi0/2": 100}, honor_lldp_med=False).assign("Gi0/2", 200)
