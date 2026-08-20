# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-vrrp-hsrp - FHRP takeover (VRRP/HSRP)."""

from netlab_vrrp_hsrp.__version__ import __version__
from netlab_vrrp_hsrp.fhrp import VirtualRouter

__all__ = ["VirtualRouter", "__version__"]
