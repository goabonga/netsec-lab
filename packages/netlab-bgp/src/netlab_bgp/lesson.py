# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-bgp - feeds `netlab-bgp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="bgp",
    layer="L3",
    title="BGP hijack (simulated)",
    summary="Hijack a prefix in a lab AS mesh - flagship module.",
    attack=[
        "Prefix / subprefix hijack",
        "Route leak between ASes",
    ],
    defense=[
        "RPKI / ROA origin validation",
        "max-prefix, AS-path filters",
    ],
)
