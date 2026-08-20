# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching brief for netlab-kerberos-net - feeds `netlab-kerberos-net brief` and the doc page."""

from __future__ import annotations

from netlab_core import Lesson

LESSON = Lesson(
    slug="kerberos-net",
    layer="Services",
    title="Kerberos on the wire",
    summary="Capture/relay Kerberos tickets at the network level.",
    attack=[
        "Capture AS/TGS exchanges on the wire",
        "Ticket relay",
    ],
    defense=[
        "PKINIT, channel binding",
        "Strong encryption, relay protection",
    ],
    scope_note="Network dimension only - not application-level ticket exploitation.",
)
