# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-amplif: amplification factors and BCP38 (simulator)."""

from __future__ import annotations

import argparse

from netlab_amplif.factor import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
