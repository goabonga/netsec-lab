# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-netflow - feeds `netlab-netflow brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="netflow",
    layer="Tooling",
    title="NetFlow / IPFIX analysis",
    summary="Generate and analyze flows for behavioural detection.",
    attack=[],
    defense=[
        "Export NetFlow/IPFIX",
        "Detect scans/exfil by flow profile",
    ],
)
