# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defend side of netlab-macsec-monitor: report per-port MACsec status (simulator)."""

from __future__ import annotations

import argparse

from netlab_macsec_monitor.monitor import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
