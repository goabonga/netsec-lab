# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-mdns-llmnr - feeds `netlab-mdns-llmnr brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="mdns-llmnr",
    layer="Services",
    title="mDNS/LLMNR/NBT-NS poisoning",
    summary="Poison LAN name resolution (network dimension, on the wire).",
    attack=[
        "Answer mDNS/LLMNR/NBT-NS queries",
    ],
    defense=[
        "Disable LLMNR and NBT-NS",
        "Segmentation",
    ],
    scope_note="Network dimension only (the wire) - no AD/application exploitation.",
)
