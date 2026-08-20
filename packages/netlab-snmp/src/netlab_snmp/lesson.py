# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-snmp - feeds `netlab-snmp brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="snmp",
    layer="Services",
    title="SNMP enumeration",
    summary="Enumerate via weak community strings.",
    attack=[
        "Brute communities (public/private)",
        "Walk the MIB",
    ],
    defense=[
        "SNMPv3 (auth+priv)",
        "Management ACL",
    ],
)
