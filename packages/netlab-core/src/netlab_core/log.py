# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Readable shared logging: uniform coloured verdicts."""

from __future__ import annotations

_ICONS = {"FORWARD": "OK", "DROP": "XX", "LEARN": "++", "ALERT": "!!", "INFO": ".."}


def verdict(kind: str, message: str, *, context: str = "") -> None:
    """Print a normalized verdict line (FORWARD/DROP/LEARN/ALERT)."""
    icon = _ICONS.get(kind, "..")
    ctx = f" {context}" if context else ""
    print(f"[{icon}] {kind:8}{ctx}  {message}")
