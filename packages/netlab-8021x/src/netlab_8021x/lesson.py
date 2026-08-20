# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-8021x - feeds `netlab-8021x brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="8021x",
    layer="L2",
    title="NAC bypass (802.1X)",
    summary="Bypass 802.1X network access control.",
    attack=[
        "MAB spoofing: clone a trusted device MAC (printer)",
        "Out-of-band hub injection behind an authenticated host",
    ],
    defense=[
        "Dynamic device profiling",
        "MACsec (802.1AE) link encryption",
    ],
)
