# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""802.1X / MAB NAC simulator: switch-side view.

A port stays closed until the device authenticates with 802.1X (EAP). The MAC
Authentication Bypass fallback instead trusts a device's MAC, so cloning a
printer's MAC opens the port. Device profiling closes the gap: the cloned MAC is
rejected because it no longer matches the expected device profile. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class NacPort:
    dot1x_ok: bool = False
    mab_allow: dict[str, str] = field(default_factory=dict)  # MAC -> expected profile
    require_profile: bool = False

    def admit(self, mac: str, profile: str | None = None) -> bool:
        """Return True if the device is admitted onto the port."""
        if self.dot1x_ok:
            verdict("FORWARD", "802.1X authenticated", context=mac)
            return True
        if mac in self.mab_allow:
            expected = self.mab_allow[mac]
            if self.require_profile and profile != expected:
                verdict(
                    "DROP",
                    f"MAB MAC but profile '{profile}' != '{expected}' -> CLONED MAC",
                    context=mac,
                )
                return False
            verdict("FORWARD", f"MAB ({expected})", context=mac)
            return True
        verdict("DROP", "not 802.1X authenticated and not in MAB list", context=mac)
        return False


def demo() -> None:
    """Reference scenario: an attacker clones a printer MAC to bypass NAC."""
    printer = "00:11:22:33:44:55"
    print("--- 1) MAB without profiling: cloned printer MAC opens the port ---")
    NacPort(mab_allow={printer: "printer"}).admit(printer, profile="workstation")
    print("\n--- 2) MAB with device profiling: the clone is rejected ---")
    NacPort(mab_allow={printer: "printer"}, require_profile=True).admit(
        printer, profile="workstation"
    )
