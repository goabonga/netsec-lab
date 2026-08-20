# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-ntp: demonstrate NTS authenticated time (simulator)."""

from __future__ import annotations

import argparse

from netlab_ntp.clock import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
