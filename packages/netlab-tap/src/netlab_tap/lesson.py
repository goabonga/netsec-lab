# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-tap - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="tap",
    layer="L1",
    title="Passive network tapping",
    summary="Intercept traffic by tapping the physical medium (copper or fibre).",
    attack=[
        "Inline TAP / vampire tap on copper",
        "Fibre tapping via a bend coupler",
    ],
    defense=[
        "MACsec (802.1AE) link encryption",
        "Tamper-evident cabling and conduit",
    ],
    scope_note="Requires physical access and a TAP/optical coupler - conceptual here.",
)
