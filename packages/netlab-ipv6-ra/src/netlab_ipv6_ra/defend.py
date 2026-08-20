# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-ipv6-ra: demonstrate RA Guard (simulator)."""

from __future__ import annotations

import argparse

from netlab_ipv6_ra.raguard import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
