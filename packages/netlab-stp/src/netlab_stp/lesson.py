# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-stp - feeds `netlab-stp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="stp",
    layer="L2",
    title="STP root takeover",
    summary="Forge BPDUs to become root bridge and reroute traffic.",
    attack=[
        "Emit a superior BPDU",
        "Take the root role, reroute flows",
    ],
    defense=[
        "BPDU Guard, Root Guard",
        "PortFast limited to access ports",
    ],
)
