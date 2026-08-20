# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""ESS monitor simulator: detecting an evil twin AP.

A legitimate SSID is served by a known set of BSSIDs. A new BSSID advertising a
known SSID is a candidate evil twin; enterprise auth (802.1X/EAP-TLS with server
certificate validation) additionally stops clients trusting it. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class EssMonitor:
    legit: dict[str, set[str]] = field(default_factory=dict)  # SSID -> sanctioned BSSIDs

    def observe(self, ssid: str, bssid: str) -> bool:
        """Return True if the (SSID, BSSID) is sanctioned, False if a candidate twin."""
        sanctioned = self.legit.get(ssid, set())
        if bssid in sanctioned:
            verdict("FORWARD", f"{ssid} on sanctioned BSSID {bssid}")
            return True
        verdict("ALERT", f"{ssid} on unknown BSSID {bssid} -> EVIL TWIN")
        return False


def demo() -> None:
    """Reference scenario: the real AP vs a twin advertising the same SSID."""
    mon = EssMonitor(legit={"corp-wifi": {"aa:bb:cc:00:00:01"}})
    print("--- 1) the real corporate AP ---")
    mon.observe("corp-wifi", "aa:bb:cc:00:00:01")
    print("\n--- 2) an evil twin cloning the SSID ---")
    mon.observe("corp-wifi", "66:66:66:66:66:66")
