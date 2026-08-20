# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-mdns-llmnr - mDNS/LLMNR/NBT-NS poisoning."""

from netlab_mdns_llmnr.__version__ import __version__
from netlab_mdns_llmnr.resolution import NameResolution

__all__ = ["NameResolution", "__version__"]
