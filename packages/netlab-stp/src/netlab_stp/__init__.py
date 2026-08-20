# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-stp - STP root takeover."""

from netlab_stp.__version__ import __version__
from netlab_stp.bpdu import Bridge

__all__ = ["Bridge", "__version__"]
