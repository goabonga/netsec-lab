# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-ids - feeds `netlab-ids brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="ids",
    layer="Tooling",
    title="IDS rule harness",
    summary="Write Snort/Suricata rules and trigger them with the PoC traffic.",
    attack=[],
    defense=[
        "Replay PoC traffic against rules",
        "Measure detection / false positives",
    ],
)
