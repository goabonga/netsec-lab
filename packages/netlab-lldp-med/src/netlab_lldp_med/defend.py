# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-lldp-med: demonstrate a static voice-VLAN policy."""

from __future__ import annotations

import argparse

from netlab_lldp_med.policy import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
