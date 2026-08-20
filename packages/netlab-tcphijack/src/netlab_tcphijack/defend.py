# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-tcphijack: demonstrate sequence-window checking (simulator)."""

from __future__ import annotations

import argparse

from netlab_tcphijack.session import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
