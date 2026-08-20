# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-portscan: demonstrate scan detection (simulator)."""

from __future__ import annotations

import argparse

from netlab_portscan.scandet import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
