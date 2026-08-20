# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-kerberos-net: demonstrate enctype strength (simulator)."""

from __future__ import annotations

import argparse

from netlab_kerberos_net.enctype import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
