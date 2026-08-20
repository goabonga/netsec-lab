# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Passive-tap exposure simulator: what a wiretap actually yields.

A passive tap copies the signal on the medium without touching the link, so it is
essentially undetectable. What it *yields* depends on encryption: on a MACsec /
IPsec link it captures only ciphertext; on a cleartext link everything is
readable. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class TappedLink:
    encrypted: bool = False

    def capture(self) -> bool:
        """Return True if the tap yields readable plaintext, False if only ciphertext."""
        if self.encrypted:
            verdict("FORWARD", "tap captures ciphertext (MACsec/IPsec) -> useless")
            return False
        verdict("ALERT", "tap captures plaintext -> full exposure")
        return True


def demo() -> None:
    """Reference scenario: a tap on a cleartext link vs an encrypted link."""
    print("--- 1) cleartext link ---")
    TappedLink(encrypted=False).capture()
    print("\n--- 2) MACsec/IPsec-encrypted link ---")
    TappedLink(encrypted=True).capture()
