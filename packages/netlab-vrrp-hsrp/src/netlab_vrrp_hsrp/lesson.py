# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-vrrp-hsrp - feeds `netlab-vrrp-hsrp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="vrrp-hsrp",
    layer="L3",
    title="FHRP takeover (VRRP/HSRP)",
    summary="Seize the master role of a redundant gateway.",
    attack=[
        "Advertise a higher VRRP/HSRP priority",
        "Become master -> MITM",
    ],
    defense=[
        "FHRP authentication",
        "Priority hardening",
    ],
)
