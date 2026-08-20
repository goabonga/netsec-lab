# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defend side of netlab-pcap-forensics: triage a synthetic capture (simulator)."""

from __future__ import annotations

import argparse

from netlab_pcap_forensics.analysis import demo


def run(args: argparse.Namespace) -> int:
    demo()
    return 0
