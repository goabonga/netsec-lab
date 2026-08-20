# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-core - shared foundation for the netsec-lab network-security PoC."""

from __future__ import annotations

from netlab_core.__version__ import __version__
from netlab_core.binding import Binding, BindingTable
from netlab_core.consent import ConsentError, add_consent_arg, require_consent
from netlab_core.lesson import Lesson
from netlab_core.log import verdict

__all__ = [
    "Binding",
    "BindingTable",
    "ConsentError",
    "Lesson",
    "__version__",
    "add_consent_arg",
    "require_consent",
    "verdict",
]
