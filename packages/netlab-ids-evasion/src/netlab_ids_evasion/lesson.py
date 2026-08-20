# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-ids-evasion - feeds `netlab-ids-evasion brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="ids-evasion",
    layer="L4",
    title="NIDS evasion (insertion/evasion)",
    summary="Ptacek-Newsham techniques: insertion/evasion, TCP desync - flagship.",
    attack=[
        "Manipulate TTL/fragmentation (insertion vs evasion)",
        "Desynchronize TCP state",
    ],
    defense=[
        "Flow normalization (traffic scrubbing)",
        "Host-state-aware IDS",
    ],
)
