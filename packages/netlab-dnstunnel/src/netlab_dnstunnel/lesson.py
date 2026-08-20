# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-dnstunnel - feeds `netlab-dnstunnel brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="dnstunnel",
    layer="Services",
    title="DNS tunneling",
    summary="Exfiltrate data encoded in DNS queries.",
    attack=[
        "Encode exfil in subdomains / TXT",
    ],
    defense=[
        "DNS entropy and volume detection",
    ],
)
