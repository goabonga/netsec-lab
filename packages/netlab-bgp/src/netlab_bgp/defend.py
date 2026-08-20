# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-bgp: demonstrate RPKI/ROA origin validation (simulator)."""

from __future__ import annotations

import argparse

from netlab_bgp.rpki import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
