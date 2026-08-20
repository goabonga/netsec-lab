# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-8021x: demonstrate MAB + device profiling (simulator)."""

from __future__ import annotations

import argparse

from netlab_8021x.nac import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
