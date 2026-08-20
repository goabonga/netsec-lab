# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-amplif - feeds `netlab-amplif brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="amplif",
    layer="L4",
    title="Reflection & amplification",
    summary="Measure the amplification factor (DNS/NTP/memcached) in-lab.",
    attack=[
        "Spoofed request -> amplified reply toward the victim (lab-measured)",
    ],
    defense=[
        "Source anti-spoofing (BCP38)",
        "Disable recursion / monlist",
    ],
)
