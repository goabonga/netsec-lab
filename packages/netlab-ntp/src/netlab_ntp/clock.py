# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""NTP time-shift simulator: why the clock is a security dependency.

TLS validity windows, Kerberos ticket lifetimes, certificate expiry and TOTP all
trust the clock. An on-path attacker who shifts a victim's NTP time can make
expired material look valid. NTS (Network Time Security) authenticates the time
source. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class NtpClient:
    nts: bool = False

    def apply(self, offset_s: float, authenticated: bool = False) -> bool:
        """Return True if the offset is applied (clock shifted), False if rejected."""
        if self.nts and not authenticated:
            verdict("DROP", "unauthenticated time source rejected (NTS)")
            return False
        verdict("ALERT", f"clock shifted by {offset_s:+.0f}s -> TLS/Kerberos windows broken")
        return True


def demo() -> None:
    """Reference scenario: a forged time shift against a plain client vs NTS."""
    print("--- 1) plain NTP client (attacker shifts the clock) ---")
    NtpClient(nts=False).apply(offset_s=-31_536_000)  # roll back a year
    print("\n--- 2) NTS client (unauthenticated time rejected) ---")
    NtpClient(nts=True).apply(offset_s=-31_536_000, authenticated=False)
