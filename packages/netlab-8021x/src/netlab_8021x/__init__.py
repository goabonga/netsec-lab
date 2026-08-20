# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-8021x - NAC bypass (802.1X)."""

from netlab_8021x.__version__ import __version__
from netlab_8021x.nac import NacPort

__all__ = ["NacPort", "__version__"]
