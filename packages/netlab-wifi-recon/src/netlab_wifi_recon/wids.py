# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Airspace / WIDS simulator: the monitoring-side control for 802.11 recon.

Passive recon is unstoppable, but a wireless IDS can compare observed BSSIDs
against an allowlist of sanctioned access points and flag anything else as a
rogue AP. Pure logic - safe to run anywhere (the sniffing itself needs a
monitor-mode radio).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class Airspace:
    known_bssids: set[str] = field(default_factory=set)  # sanctioned APs
    seen: set[str] = field(default_factory=set)

    def observe(self, ssid: str, bssid: str) -> bool:
        """Return True if the AP is sanctioned, False if it is a rogue."""
        self.seen.add(bssid)
        if bssid in self.known_bssids:
            verdict("FORWARD", f"known AP {ssid} ({bssid})")
            return True
        verdict("ALERT", f"unknown AP {ssid} ({bssid}) -> ROGUE AP")
        return False


def demo() -> None:
    """Reference scenario: a sanctioned AP vs an unknown one."""
    wids = Airspace(known_bssids={"aa:bb:cc:00:00:01"})
    print("--- 1) sanctioned corporate AP ---")
    wids.observe("corp-wifi", "aa:bb:cc:00:00:01")
    print("\n--- 2) unknown AP in the airspace ---")
    wids.observe("corp-wifi", "66:66:66:66:66:66")
