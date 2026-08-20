# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defend side of netlab-tls-inspect: enforce an SNI allowlist (simulator)."""

from __future__ import annotations

import argparse

from netlab_tls_inspect.handshake import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
