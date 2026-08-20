# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-hw-implant: demonstrate NAC / asset inventory (simulator)."""

from __future__ import annotations

import argparse

from netlab_hw_implant.inventory import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
