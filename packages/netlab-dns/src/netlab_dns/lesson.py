# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-dns - feeds `netlab-dns brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="dns",
    layer="Services",
    title="DNS spoofing / cache poisoning",
    summary="Poison a resolver to hijack a name resolution.",
    attack=[
        "Race the resolver",
        "Inject a forged answer",
    ],
    defense=[
        "DNSSEC",
        "Source-port + QID randomization",
    ],
)
