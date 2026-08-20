# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-igmp - feeds `netlab-igmp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="igmp",
    layer="L3",
    title="IGMP snooping / spoofing",
    summary="Manipulate multicast membership (forged join/leave).",
    attack=[
        "Forge IGMP joins/leaves",
        "Multicast eavesdrop / DoS",
    ],
    defense=[
        "IGMP snooping, querier control",
    ],
)
