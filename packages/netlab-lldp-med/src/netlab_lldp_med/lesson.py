# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-lldp-med - feeds `netlab-lldp-med brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="lldp-med",
    layer="L2",
    title="LLDP-MED abuse",
    summary="Abuse LLDP-MED to spoof the voice VLAN / PoE policy.",
    attack=[
        "Advertise a bogus voice VLAN",
        "Negotiate an undue PoE class",
    ],
    defense=[
        "Authenticated provisioning",
        "Static per-port voice VLAN",
    ],
)
