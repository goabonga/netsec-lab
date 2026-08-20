# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-pcap-forensics - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="pcap-forensics",
    layer="Tooling",
    title="PCAP forensics",
    summary="Reconstruct an attack from a capture (blue-team exercise).",
    attack=[],
    defense=[
        "Analyze a pcap",
        "Rebuild the attack timeline",
    ],
)
