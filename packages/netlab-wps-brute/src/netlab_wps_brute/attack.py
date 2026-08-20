# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-wps-brute: enumerate the reduced WPS PIN space. LAB ONLY.

Shows the two-halves search-space collapse (runnable without a radio) and, on a
monitor-mode NIC, would drive the online PIN brute (reaver). Only ever against an
AP you own.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict

from netlab_wps_brute.pin import brute_attempts, is_valid


def run(args: argparse.Namespace) -> int:
    verdict("ALERT", f"reduced search space: {brute_attempts(two_halves=True)} PINs")
    valid = sum(1 for p in range(args.sample) if is_valid(p))
    verdict("INFO", f"{valid}/{args.sample} candidate PINs pass the checksum")
    print("[*] the online brute against a real AP needs a monitor-mode NIC (reaver).")
    return 0
