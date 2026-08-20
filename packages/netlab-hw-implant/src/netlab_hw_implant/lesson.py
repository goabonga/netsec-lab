# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-hw-implant - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="hw-implant",
    layer="L1",
    title="Rogue hardware implant",
    summary="Drop a covert network device (implant / BadUSB) onto the wire.",
    attack=[
        "Inline implant / drop box (LAN tap + radio)",
        "BadUSB network adapter",
    ],
    defense=[
        "802.1X port-based NAC, MACsec",
        "Physical port security and asset inventory",
    ],
    scope_note="Requires physical device placement - conceptual here.",
)
