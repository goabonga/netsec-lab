# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-discovery - feeds `netlab-discovery brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="discovery",
    layer="L2",
    title="CDP/LLDP enumeration",
    summary="Map and spoof topology via CDP/LLDP.",
    attack=[
        "Harvest neighbours, VLANs, models",
        "Spoof a neighbour",
    ],
    defense=[
        "Disable CDP/LLDP on access ports",
    ],
)
