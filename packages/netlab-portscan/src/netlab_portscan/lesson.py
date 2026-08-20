# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-portscan - feeds `netlab-portscan brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="portscan",
    layer="L4",
    title="Port scanning & fingerprinting",
    summary="Scanning techniques and TCP/IP stack fingerprinting.",
    attack=[
        "SYN/FIN/NULL/Xmas scans",
        "OS fingerprint (TCP options, TTL)",
    ],
    defense=[
        "Scan detection, rate-limit",
        "Drop stealth scans",
    ],
)
