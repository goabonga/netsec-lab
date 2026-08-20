# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-synflood - feeds `netlab-synflood brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="synflood",
    layer="L4",
    title="TCP SYN flood",
    summary="Exhaust the connection table with half-open connections.",
    attack=[
        "SYN flood with spoofed source",
        "Backlog saturation",
    ],
    defense=[
        "SYN cookies",
        "conntrack limits, SYN rate-limit",
    ],
)
