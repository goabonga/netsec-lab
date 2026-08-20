# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-wifi-recon: demonstrate WIDS rogue-AP detection (simulator)."""

from __future__ import annotations

import argparse

from netlab_wifi_recon.wids import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
