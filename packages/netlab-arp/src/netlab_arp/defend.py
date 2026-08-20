# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-arp: demonstrate Dynamic ARP Inspection (simulator)."""

from __future__ import annotations

import argparse

from netlab_arp.dai import demo


def run(args: argparse.Namespace) -> int:
    dai = demo()
    print("\n=== binding table (from DHCP snooping) ===")
    for b in dai.bindings:
        print(f"{b.mac}  {b.ip}  {b.port}")
    return 0
