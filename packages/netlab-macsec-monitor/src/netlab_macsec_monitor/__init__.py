# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-macsec-monitor - MACsec link monitor."""

from netlab_macsec_monitor.__version__ import __version__
from netlab_macsec_monitor.monitor import PortState, check

__all__ = ["PortState", "__version__", "check"]
