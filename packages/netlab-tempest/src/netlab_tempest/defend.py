# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-tempest: demonstrate shielding (link-budget simulator)."""

from __future__ import annotations

import argparse

from netlab_tempest.emanation import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
