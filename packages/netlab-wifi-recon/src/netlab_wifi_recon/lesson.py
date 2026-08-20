# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-wifi-recon - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="wifi-recon",
    layer="L1",
    title="802.11 passive reconnaissance",
    summary="Harvest SSIDs, BSSIDs and clients from the air, passively.",
    attack=[
        "Sniff beacons/probe requests in monitor mode",
        "Map APs, clients and hidden SSIDs",
    ],
    defense=[
        "Minimise beacon info; treat SSID hiding as weak",
        "WIDS/WIPS airspace monitoring",
    ],
    scope_note="Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.",
)
