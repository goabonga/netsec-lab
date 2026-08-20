# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-wps-brute: flag repeated WPS registrar failures."""

from __future__ import annotations

import argparse

from netlab_core import verdict


def run(args: argparse.Namespace) -> int:
    verdict(
        "INFO",
        f"monitor WPS M4/M6 NACK rate on {args.iface}: a burst of failures is a PIN brute; "
        "lock out after the threshold",
    )
    return 0
