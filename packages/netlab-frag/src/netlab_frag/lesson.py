# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-frag - feeds `netlab-frag brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="frag",
    layer="L3",
    title="Fragmentation & IDS evasion",
    summary="Overlapping fragments to defeat IDS reassembly.",
    attack=[
        "Overlapping fragments",
        "Divergent order/TTL host vs IDS",
    ],
    defense=[
        "Full reassembly on the IDS",
        "Drop overlaps",
    ],
)
