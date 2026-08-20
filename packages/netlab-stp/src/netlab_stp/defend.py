# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-stp: demonstrate BPDU Guard / root election (simulator)."""

from __future__ import annotations

import argparse

from netlab_stp.bpdu import demo


def run(args: argparse.Namespace) -> int:
    bridge = demo()
    print(f"\nbridge believes root priority = {bridge.root_priority}")
    return 0
