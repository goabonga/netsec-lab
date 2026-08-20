# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-dhcp - feeds `netlab-dhcp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="dhcp",
    layer="L2",
    title="DHCP snooping",
    summary="Rogue DHCP server (MITM) and DHCP starvation against a pool.",
    attack=[
        "Rogue server: answer OFFER/ACK with attacker gw/DNS -> MITM",
        "Starvation: flood DISCOVER with random MACs to drain the pool",
    ],
    defense=[
        "DHCP snooping: trusted/untrusted ports, drop untrusted OFFER",
        "IP Source Guard from the binding table",
        "Per-port DISCOVER rate-limit",
    ],
)
