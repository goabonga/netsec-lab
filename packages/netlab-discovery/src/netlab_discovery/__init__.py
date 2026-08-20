# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-discovery - CDP/LLDP enumeration."""

from netlab_discovery.__version__ import __version__
from netlab_discovery.policy import DiscoveryPolicy, Neighbour

__all__ = ["DiscoveryPolicy", "Neighbour", "__version__"]
