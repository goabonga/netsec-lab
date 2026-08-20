# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-vlan - feeds `netlab-vlan brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="vlan",
    layer="L2",
    title="VLAN hopping",
    summary="Escape your VLAN via DTP negotiation or 802.1Q double tagging.",
    attack=[
        "Switch spoofing via DTP",
        "802.1Q double tagging into a target VLAN",
    ],
    defense=[
        "Disable DTP (nonegotiate)",
        "Dedicated, unused native VLAN",
    ],
)
