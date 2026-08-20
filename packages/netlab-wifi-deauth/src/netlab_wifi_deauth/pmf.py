# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""802.11w Protected Management Frames simulator: the association-side defence.

In the original standard, deauthentication frames are unauthenticated, so anyone
can forge one and drop a client. 802.11w cryptographically protects management
frames, so a forged deauth fails the integrity check and is ignored. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class Association:
    pmf: bool = False  # 802.11w Protected Management Frames

    def on_deauth(self, authentic: bool) -> bool:
        """Return True if the association is torn down, False if the deauth is ignored."""
        if self.pmf and not authentic:
            verdict("DROP", "forged deauth ignored (802.11w PMF)")
            return False
        verdict("ALERT", "deauth accepted -> client disconnected")
        return True


def demo() -> None:
    """Reference scenario: a forged deauth against an unprotected vs a PMF association."""
    print("--- 1) no PMF: forged deauth disconnects the client ---")
    Association(pmf=False).on_deauth(authentic=False)
    print("\n--- 2) 802.11w PMF: forged deauth is ignored ---")
    Association(pmf=True).on_deauth(authentic=False)
