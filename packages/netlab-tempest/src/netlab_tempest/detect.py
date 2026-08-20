# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-tempest: emanation eavesdropping is passive."""

from __future__ import annotations

import argparse

from netlab_core import verdict


def run(args: argparse.Namespace) -> int:
    verdict(
        "INFO",
        "TEMPEST eavesdropping is fully passive and undetectable from the network; "
        "the control is physical - shielding, EMSEC zoning and TEMPEST-rated equipment",
    )
    return 0
