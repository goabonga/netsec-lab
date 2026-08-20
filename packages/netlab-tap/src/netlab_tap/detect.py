# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-tap: passive taps are largely undetectable."""

from __future__ import annotations

import argparse

from netlab_core import verdict


def run(args: argparse.Namespace) -> int:
    verdict(
        "INFO",
        "a passive tap adds no latency and sends nothing, so it is essentially "
        "undetectable on the wire - use time-domain reflectometry / cable "
        "inspection, and encrypt the link so a tap yields only ciphertext",
    )
    return 0
