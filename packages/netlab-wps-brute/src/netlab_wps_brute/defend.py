# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-wps-brute: demonstrate the PIN search-space maths (simulator)."""

from __future__ import annotations

import argparse

from netlab_wps_brute.pin import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
