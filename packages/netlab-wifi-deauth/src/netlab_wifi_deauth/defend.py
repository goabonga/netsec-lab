# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-wifi-deauth: demonstrate 802.11w PMF (simulator)."""

from __future__ import annotations

import argparse

from netlab_wifi_deauth.pmf import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
