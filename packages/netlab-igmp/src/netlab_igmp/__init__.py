# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-igmp - IGMP snooping / spoofing."""

from netlab_igmp.__version__ import __version__
from netlab_igmp.snoop import SnoopController

__all__ = ["SnoopController", "__version__"]
