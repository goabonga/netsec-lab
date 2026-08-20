# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-covert: demonstrate header normalization (simulator)."""

from __future__ import annotations

import argparse

from netlab_covert.channel import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
