# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-tap: demonstrate link encryption vs a tap (simulator)."""

from __future__ import annotations

import argparse

from netlab_tap.exposure import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
