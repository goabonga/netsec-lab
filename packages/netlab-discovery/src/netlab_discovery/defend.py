# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-discovery: demonstrate the CDP/LLDP policy (simulator)."""

from __future__ import annotations

import argparse

from netlab_discovery.policy import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
