# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-routing - Routing injection (RIP/OSPF)."""

from netlab_routing.__version__ import __version__
from netlab_routing.igp import Router

__all__ = ["Router", "__version__"]
