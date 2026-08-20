# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-routing - feeds `netlab-routing brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="routing",
    layer="L3",
    title="Routing injection (RIP/OSPF)",
    summary="Inject bogus routes into an unauthenticated IGP.",
    attack=[
        "Advertise RIP/OSPF routes",
        "Blackhole / reroute",
    ],
    defense=[
        "Neighbour authentication (MD5/SHA)",
        "Passive interfaces",
    ],
)
