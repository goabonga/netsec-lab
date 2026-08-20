# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-tcphijack - feeds `netlab-tcphijack brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="tcphijack",
    layer="L4",
    title="TCP session hijacking",
    summary="Inject into / reset an established TCP session.",
    attack=[
        "RST injection",
        "Sequence-number prediction, hijack",
    ],
    defense=[
        "ISN randomization",
        "TCP-AO / integrity",
    ],
)
