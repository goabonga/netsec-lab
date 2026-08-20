# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-ipspoof - feeds `netlab-ipspoof brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="ipspoof",
    layer="L3",
    title="IP spoofing",
    summary="Forge the source IP; foundation of many L3/L4 attacks.",
    attack=[
        "Forge the source IP",
        "Blind spoofing / reflection",
    ],
    defense=[
        "BCP38 ingress/egress filtering",
        "Strict uRPF",
    ],
)
