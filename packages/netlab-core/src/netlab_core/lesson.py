# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Teaching-brief model: each PoC describes what it teaches, the attack and
the defense, rendered by the `brief` subcommand and the docs.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Lesson:
    slug: str
    layer: str
    title: str
    summary: str
    attack: list[str] = field(default_factory=list)
    defense: list[str] = field(default_factory=list)
    scope_note: str = ""

    def render(self) -> str:
        lines = [
            f"# {self.title}  [{self.layer}]",
            "",
            self.summary,
        ]
        if self.scope_note:
            lines += ["", f"> Scope: {self.scope_note}"]
        lines += ["", "## Attack"]
        lines += [f"  {i}. {s}" for i, s in enumerate(self.attack, 1)] or ["  (defensive module)"]
        lines += ["", "## Defense"]
        lines += [f"  - {s}" for s in self.defense]
        return "\n".join(lines)
