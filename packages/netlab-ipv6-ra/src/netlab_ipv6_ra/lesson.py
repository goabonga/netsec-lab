# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-ipv6-ra - feeds `netlab-ipv6-ra brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="ipv6-ra",
    layer="L2",
    title="Rogue Router Advertisement (IPv6)",
    summary="The IPv6 equivalent of rogue DHCP: forge RA/SLAAC messages.",
    attack=[
        "Emit forged RAs -> attacker gateway/DNS",
        "Malicious RDNSS option",
    ],
    defense=[
        "RA Guard on access ports",
        "SEND (Secure Neighbor Discovery)",
    ],
)
