# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defend side of netlab-ids: score the rule set against labelled traffic."""

from __future__ import annotations

import argparse

from netlab_ids.rules import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
