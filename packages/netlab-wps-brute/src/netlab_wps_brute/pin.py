# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""WPS PIN maths: why an 8-digit PIN is not 10^8 of work, runnable without a radio.

The 8th digit is a checksum of the first seven, and the registrar validates the
PIN in two halves - revealing which half is wrong. That cuts the brute-force
search from 10^7 valid PINs to ~11000 attempts. The fix is to disable WPS (or
lock out after failures). Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from netlab_core import verdict


def checksum(pin7: int) -> int:
    """WPS checksum digit for a 7-digit PIN."""
    accum = 0
    accum += 3 * (pin7 // 10000000 % 10)
    accum += pin7 // 1000000 % 10
    accum += 3 * (pin7 // 100000 % 10)
    accum += pin7 // 10000 % 10
    accum += 3 * (pin7 // 1000 % 10)
    accum += pin7 // 100 % 10
    accum += 3 * (pin7 // 10 % 10)
    accum += pin7 % 10
    return (10 - accum % 10) % 10


def is_valid(pin8: int) -> bool:
    """Return True if the 8-digit PIN has a correct checksum digit."""
    return checksum(pin8 // 10) == pin8 % 10


def brute_attempts(two_halves: bool) -> int:
    """Worst-case attempts: naive 10^7 valid PINs vs the two-halves reduction."""
    return (10**4 + 10**3) if two_halves else 10**7


def demo() -> None:
    """Reference scenario: the two-halves search-space collapse."""
    naive = brute_attempts(two_halves=False)
    reduced = brute_attempts(two_halves=True)
    verdict(
        "ALERT",
        f"two-halves brute: {reduced} attempts vs {naive} naive (~{naive // reduced}x faster)",
    )
    print("\n--- fix: disable WPS, or lock out after N failed PINs ---")
    verdict("FORWARD", "WPS disabled -> no PIN to brute")
