# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defend side of netlab-firewall: demonstrate the default-deny stateful policy."""

from __future__ import annotations

import argparse

from netlab_firewall.acl import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
