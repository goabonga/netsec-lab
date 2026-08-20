# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-vlan - VLAN hopping."""

from netlab_vlan.__version__ import __version__
from netlab_vlan.hop import Frame, VlanSwitch

__all__ = ["Frame", "VlanSwitch", "__version__"]
