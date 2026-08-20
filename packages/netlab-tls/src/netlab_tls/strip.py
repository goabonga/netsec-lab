# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""SSL-strip / HSTS simulator: the client-side bootstrap defence.

TLS protects a session once established, but an on-path attacker can keep a
victim on plaintext HTTP by rewriting links (SSL stripping). HSTS tells the
browser to always use HTTPS for a site, so the downgrade fails. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class Browser:
    hsts: bool = False

    def navigate(self, requested_scheme: str) -> str:
        """Return the effective scheme after an on-path attacker's attempt."""
        if requested_scheme == "http" and self.hsts:
            verdict("FORWARD", "HSTS -> forced upgrade to https")
            return "https"
        if requested_scheme == "http":
            verdict("ALERT", "SSL stripped -> plaintext http (credentials exposed)")
            return "http"
        verdict("FORWARD", "https")
        return "https"


def demo() -> None:
    """Reference scenario: SSL strip against a browser without vs with HSTS."""
    print("--- 1) browser without HSTS (attacker downgrades) ---")
    Browser(hsts=False).navigate("http")
    print("\n--- 2) browser with HSTS (upgrade forced) ---")
    Browser(hsts=True).navigate("http")
