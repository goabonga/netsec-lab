# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-tls - feeds `netlab-tls brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="tls",
    layer="Services",
    title="TLS downgrade / MITM",
    summary="SSL stripping, downgrade and proxy MITM.",
    attack=[
        "SSL strip (HTTP<->HTTPS)",
        "Version downgrade, bogus cert",
    ],
    defense=[
        "HSTS (preload)",
        "Pinning, strict chain validation",
    ],
)
