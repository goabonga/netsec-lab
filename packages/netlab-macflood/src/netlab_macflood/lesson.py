# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-macflood - feeds `netlab-macflood brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="macflood",
    layer="L2",
    title="MAC flooding (CAM overflow)",
    summary="Saturate the switch CAM table to force fail-open (hub) behaviour.",
    attack=[
        "Flood frames with random source MACs",
        "Sniff the fail-open traffic",
    ],
    defense=[
        "Port security: per-port MAC limit",
        "Sticky MAC, shutdown on violation",
    ],
)
