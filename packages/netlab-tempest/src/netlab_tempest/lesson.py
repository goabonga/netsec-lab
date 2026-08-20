# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-tempest - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="tempest",
    layer="L1",
    title="TEMPEST / Van Eck emanations",
    summary="Reconstruct data from unintended electromagnetic emanations.",
    attack=[
        "Capture EM emanations (screen/cable)",
        "Reconstruct the leaked signal",
    ],
    defense=[
        "Shielding (Faraday), EMSEC zoning",
        "TEMPEST-rated equipment",
    ],
    scope_note="Requires SDR/antenna and proximity - conceptual here.",
)
