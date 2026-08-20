# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""TEMPEST emanation simulator: a link-budget model of Van Eck eavesdropping.

Unintended electromagnetic emanations can be reconstructed only if the signal
still rises above the receiver's noise floor after free-space path loss and any
shielding. Increasing shielding (Faraday enclosures, EMSEC zoning) pushes the
received level below the noise floor. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

import math

from netlab_core import verdict

NOISE_FLOOR_DBM = -95.0


def path_loss_db(distance_m: float, freq_mhz: float = 200.0) -> float:
    """Free-space path loss (dB); 0 at the source."""
    if distance_m <= 0:
        return 0.0
    return 20 * math.log10(distance_m) + 20 * math.log10(freq_mhz) - 27.55


def reconstructable(emission_dbm: float, distance_m: float, shielding_db: float) -> bool:
    """Return True if the emanation can be reconstructed at that distance."""
    received = emission_dbm - path_loss_db(distance_m) - shielding_db
    return received > NOISE_FLOOR_DBM


def demo() -> None:
    """Reference scenario: an unshielded screen vs a shielded enclosure at 10 m."""
    emission, distance = 20.0, 10.0
    print("--- 1) unshielded equipment ---")
    ok = reconstructable(emission, distance, shielding_db=0.0)
    verdict("ALERT" if ok else "FORWARD", f"reconstructable at {distance} m: {ok}")
    print("\n--- 2) TEMPEST shielding (Faraday enclosure, 100 dB) ---")
    ok2 = reconstructable(emission, distance, shielding_db=100.0)
    verdict("ALERT" if ok2 else "FORWARD", f"reconstructable at {distance} m: {ok2}")
