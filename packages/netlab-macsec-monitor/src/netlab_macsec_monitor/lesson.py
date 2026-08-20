# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-macsec-monitor - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="macsec-monitor",
    layer="Tooling",
    title="MACsec posture check",
    summary="Audit MACsec posture (encrypted vs cleartext links) on a segment.",
    attack=[],
    defense=[
        "Inventory 802.1AE-protected links",
        "Alert on cleartext links",
    ],
)
