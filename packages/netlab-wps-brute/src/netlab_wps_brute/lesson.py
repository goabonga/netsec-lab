# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-wps-brute - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="wps-brute",
    layer="L1",
    title="WPS PIN brute force",
    summary="Recover the WPA PSK via the WPS PIN (online brute or Pixie-Dust).",
    attack=[
        "Online PIN brute (reaver)",
        "Pixie-Dust offline PIN recovery",
    ],
    defense=[
        "Disable WPS",
        "PIN lockout / rate-limit",
    ],
    scope_note="Requires a Wi-Fi NIC in monitor mode - not replayable in the netns lab.",
)
