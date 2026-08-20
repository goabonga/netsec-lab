# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-tls-inspect - seeds the CLI brief and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="tls-inspect",
    layer="Tooling",
    title="TLS inspection proxy",
    summary="Defensive TLS inspection proxy (SNI filtering, enterprise MITM).",
    attack=[],
    defense=[
        "SNI-based filtering",
        "Trade-offs and limits of enterprise MITM",
    ],
)
