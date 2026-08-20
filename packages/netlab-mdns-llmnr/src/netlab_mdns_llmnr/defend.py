# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-mdns-llmnr: demonstrate disabling LLMNR (simulator)."""

from __future__ import annotations

import argparse

from netlab_mdns_llmnr.resolution import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
