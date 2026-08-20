# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-wifi-deauth - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="wifi-deauth",
    layer="L1",
    title="802.11 deauthentication",
    summary="Forge deauth/disassoc frames to drop clients or force handshakes.",
    attack=[
        "Spoofed deauth flood -> DoS",
        "Force a client to re-handshake for capture",
    ],
    defense=[
        "802.11w Protected Management Frames",
        "WIPS deauth detection",
    ],
    scope_note="Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.",
)
