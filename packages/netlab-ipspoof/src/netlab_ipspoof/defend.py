# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-ipspoof: demonstrate BCP38 / uRPF (simulator)."""

from __future__ import annotations

import argparse

from netlab_ipspoof.urpf import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
