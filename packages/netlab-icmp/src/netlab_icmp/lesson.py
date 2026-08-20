# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-icmp - feeds `netlab-icmp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="icmp",
    layer="L3",
    title="ICMP redirect & tunneling",
    summary="Hijack routing via ICMP redirect; covert ICMP channel.",
    attack=[
        "ICMP redirect -> MITM",
        "Tunnel data in the ICMP payload",
    ],
    defense=[
        "Ignore redirects (sysctl)",
        "DPI / payload inspection",
    ],
)
