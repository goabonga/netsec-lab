# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""VLAN hopping simulator (802.1Q double tagging): switch-side view.

An access port assigns its VLAN to untagged frames and does not honour a frame's
own tag. A permissive switch, however, strips an outer tag equal to the trunk's
*native* VLAN and forwards the inner-tagged frame onto the trunk - so a frame
tagged [native, target] hops from the access VLAN to the target VLAN. The fix is
a dedicated, unused native VLAN (and dropping tagged frames on access ports).
Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass(frozen=True)
class Frame:
    tags: tuple[int, ...]  # 802.1Q tags, outer to inner
    ingress_port: str


@dataclass
class VlanSwitch:
    native_vlan: int = 1
    access_vlan: int = 1
    drop_tagged_on_access: bool = False

    def forward(self, frame: Frame) -> int | None:
        """Return the VLAN the frame lands on, or None if dropped."""
        port = frame.ingress_port
        if not frame.tags:
            verdict("FORWARD", f"untagged -> access VLAN {self.access_vlan}", context=port)
            return self.access_vlan
        if self.drop_tagged_on_access:
            verdict("DROP", "tagged frame on access port", context=port)
            return None
        if len(frame.tags) >= 2 and frame.tags[0] == self.native_vlan:
            inner = frame.tags[1]
            verdict("ALERT", f"double-tag [{frame.tags[0]},{inner}] -> hopped to VLAN {inner}")
            return inner
        # the access port does not honour the frame's tag: it stays on the access VLAN
        verdict("FORWARD", f"tag ignored -> access VLAN {self.access_vlan}", context=port)
        return self.access_vlan


def demo() -> None:
    """Reference scenario: a double-tagged frame vs a hardened switch."""
    print("--- 1) permissive switch (native == access VLAN 1) ---")
    VlanSwitch(native_vlan=1, access_vlan=1).forward(Frame(tags=(1, 20), ingress_port="Gi0/3"))
    print("\n--- 2) hardened switch (dedicated native VLAN 999) ---")
    VlanSwitch(native_vlan=999, access_vlan=1).forward(Frame(tags=(1, 20), ingress_port="Gi0/3"))
    print("\n--- 3) hardened switch (drop tagged frames on access ports) ---")
    VlanSwitch(native_vlan=999, drop_tagged_on_access=True).forward(
        Frame(tags=(1, 20), ingress_port="Gi0/3")
    )
