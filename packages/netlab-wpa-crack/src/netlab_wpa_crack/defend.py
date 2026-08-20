# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-wpa-crack: demonstrate weak vs strong passphrase (crypto)."""

from __future__ import annotations

import argparse

from netlab_wpa_crack.crack import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
