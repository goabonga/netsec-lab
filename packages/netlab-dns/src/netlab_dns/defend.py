# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-dns: demonstrate txid/port matching and DNSSEC (simulator)."""

from __future__ import annotations

import argparse

from netlab_dns.resolver import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
