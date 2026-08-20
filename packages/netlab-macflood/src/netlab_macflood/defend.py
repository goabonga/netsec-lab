# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-macflood: demonstrate port-security (simulator)."""

from __future__ import annotations

import argparse

from netlab_macflood.portsec import demo


def run(args: argparse.Namespace) -> int:
    port = demo()
    print(f"\nport {port.port}: shutdown={port.shutdown}")
    return 0
