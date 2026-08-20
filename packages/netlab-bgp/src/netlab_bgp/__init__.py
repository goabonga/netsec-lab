# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-bgp - BGP hijack (simulated)."""

from netlab_bgp.__version__ import __version__
from netlab_bgp.rpki import Announcement, Bgp

__all__ = ["Announcement", "Bgp", "__version__"]
