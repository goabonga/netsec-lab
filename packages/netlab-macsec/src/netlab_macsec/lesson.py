# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-macsec - feeds `netlab-macsec brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="macsec",
    layer="L2",
    title="MACsec / MKA",
    summary='The "TLS of Layer 2": point-to-point encryption + integrity.',
    attack=[
        "Attempt to replay/hijack an MKA session",
    ],
    defense=[
        "802.1AE: per-link confidentiality and integrity",
        "MKA key rotation",
    ],
)
