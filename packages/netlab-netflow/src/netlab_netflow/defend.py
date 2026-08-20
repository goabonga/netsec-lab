# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defend side of netlab-netflow: export flows and flag anomalies (simulator)."""

from __future__ import annotations

import argparse

from netlab_netflow.flow import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
