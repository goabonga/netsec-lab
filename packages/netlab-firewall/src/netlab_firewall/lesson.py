# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-firewall - feeds `netlab-firewall brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="firewall",
    layer="Tooling",
    title="Firewall policy",
    summary="nftables/iptables policy and validation that it blocks the PoC.",
    attack=[],
    defense=[
        "Write an nft/iptables policy",
        "Verify each PoC is blocked",
    ],
)
