# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Defense side of netlab-dhcp: demonstrate DHCP snooping on the switch.

Runs the dependency-free snooping simulator (see snoop.py): a legitimate DORA
exchange builds the binding table, then a rogue OFFER and a DISCOVER flood are
dropped. No root, no scapy - this is the "what the switch does" view.
"""

from __future__ import annotations

import argparse

from netlab_dhcp.snoop import demo


def run(args: argparse.Namespace) -> int:
    sw = demo()
    print("\n=== binding table ===")
    for b in sw.bindings:
        print(f"{b.mac}  {b.ip}  vlan={b.vlan}  {b.port}  {b.lease}s")
    return 0
