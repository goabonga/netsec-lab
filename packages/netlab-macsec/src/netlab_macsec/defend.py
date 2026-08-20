# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-macsec: demonstrate 802.1AE frame protection (simulator)."""

from __future__ import annotations

import argparse

from netlab_macsec.link import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
