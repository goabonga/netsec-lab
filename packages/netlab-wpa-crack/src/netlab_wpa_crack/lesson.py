# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-wpa-crack - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="wpa-crack",
    layer="L1",
    title="WPA/WPA2 handshake & PMKID crack",
    summary="Capture the 4-way handshake or PMKID and crack the PSK offline.",
    attack=[
        "Capture handshake (deauth-assisted) or PMKID",
        "Offline dictionary / GPU crack",
    ],
    defense=[
        "Long random passphrase or WPA3-SAE",
        "Enterprise auth (no shared PSK)",
    ],
    scope_note="Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.",
)
