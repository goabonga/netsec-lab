# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Amplification-factor simulator: measure reflection, contain with anti-spoofing.

A reflector answers a small spoofed request with a large reply aimed at the
victim; the amplification factor (reply/request) multiplies the attacker's
bandwidth. Source anti-spoofing (BCP38) stops the spoofed request ever reaching
a reflector. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass(frozen=True)
class Reflector:
    name: str
    request_size: int
    response_size: int

    @property
    def factor(self) -> float:
        return self.response_size / self.request_size


KNOWN = [
    Reflector("DNS ANY", 60, 3000),
    Reflector("NTP monlist", 8, 480),
    Reflector("memcached", 15, 750_000),
]


def measure(reflector: Reflector, anti_spoofing: bool) -> float:
    """Return the effective amplification (0.0 when anti-spoofing blocks it)."""
    if anti_spoofing:
        verdict("DROP", f"{reflector.name}: spoofed request blocked by BCP38")
        return 0.0
    verdict("ALERT", f"{reflector.name}: x{reflector.factor:.0f} amplification -> victim")
    return reflector.factor


def demo() -> None:
    """Reference scenario: amplification factors, then BCP38 mitigation."""
    print("--- 1) reflectors amplify the spoofed request ---")
    for r in KNOWN:
        measure(r, anti_spoofing=False)
    print("\n--- 2) BCP38 source anti-spoofing blocks the reflection ---")
    measure(KNOWN[0], anti_spoofing=True)
