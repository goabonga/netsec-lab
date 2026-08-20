# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-evil-twin: demonstrate ESS twin detection (simulator)."""

from __future__ import annotations

import argparse

from netlab_evil_twin.ess import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
