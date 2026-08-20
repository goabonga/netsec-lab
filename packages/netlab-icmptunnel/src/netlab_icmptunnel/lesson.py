# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-icmptunnel - feeds `netlab-icmptunnel brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="icmptunnel",
    layer="Services",
    title="ICMP tunneling",
    summary="Exfiltrate in ICMP echo payloads (companion to the DNS tunnel).",
    attack=[
        "Encode exfil in the echo payload",
    ],
    defense=[
        "Payload inspection, block outbound echo",
    ],
)
