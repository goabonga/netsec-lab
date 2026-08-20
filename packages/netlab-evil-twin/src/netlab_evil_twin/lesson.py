# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-evil-twin - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="evil-twin",
    layer="L1",
    title="Evil twin / rogue AP",
    summary="Clone an AP (SSID/BSSID) to MITM associating clients.",
    attack=[
        "Karma / known-beacon responses",
        "Captive-portal credential capture, MITM",
    ],
    defense=[
        "802.1X/EAP-TLS with server-cert validation",
        "WIPS rogue-AP detection",
    ],
    scope_note="Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.",
)
