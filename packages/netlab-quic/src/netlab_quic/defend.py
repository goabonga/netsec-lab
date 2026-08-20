# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-quic: demonstrate Initial-vs-short-header visibility (simulator)."""

from __future__ import annotations

import argparse

from netlab_quic.header import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
