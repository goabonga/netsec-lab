# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-portscan - Port scanning & fingerprinting."""

from netlab_portscan.__version__ import __version__
from netlab_portscan.scandet import ScanDetector

__all__ = ["ScanDetector", "__version__"]
