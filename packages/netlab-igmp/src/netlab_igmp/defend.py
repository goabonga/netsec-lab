# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-igmp: demonstrate join restriction (simulator)."""

from __future__ import annotations

import argparse

from netlab_igmp.snoop import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
