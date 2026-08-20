# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-quic - feeds `netlab-quic brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="quic",
    layer="Services",
    title="QUIC / HTTP3 fingerprinting",
    summary="Recon and inspection challenges of an encrypted UDP transport.",
    attack=[
        "Fingerprint QUIC",
        "Defeat inspection (encrypted UDP)",
    ],
    defense=[
        "SNI from the Initial packet",
        "Flow heuristics",
    ],
)
