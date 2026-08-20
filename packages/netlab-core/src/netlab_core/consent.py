# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Consent guardrail shared by every offensive PoC.

No script that emits traffic may start unless the operator explicitly
asserts they are acting on a network they own.
"""

from __future__ import annotations

import argparse

CONSENT_FLAG = "i_own_this_network"
_HELP = "assert you operate on a network you own (isolated lab)"


class ConsentError(SystemExit):
    """Raised when an offensive PoC starts without explicit consent."""


def add_consent_arg(parser: argparse.ArgumentParser) -> None:
    """Add --i-own-this-network to an offensive subcommand parser."""
    parser.add_argument("--i-own-this-network", action="store_true", help=_HELP)


def require_consent(args: argparse.Namespace) -> None:
    """Abort unless consent was given."""
    if not getattr(args, CONSENT_FLAG, False):
        raise ConsentError(
            "Refused: this PoC emits real traffic. Re-run with "
            "--i-own-this-network (isolated lab only)."
        )
