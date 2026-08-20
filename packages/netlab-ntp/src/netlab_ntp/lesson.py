# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-ntp - feeds `netlab-ntp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="ntp",
    layer="Services",
    title="NTP time-shift MITM",
    summary="Shift the clock to invalidate TLS/Kerberos.",
    attack=[
        "NTP MITM -> clock shift",
        "Break validity windows",
    ],
    defense=[
        "NTS (Network Time Security)",
        "Multiple authenticated sources",
    ],
)
