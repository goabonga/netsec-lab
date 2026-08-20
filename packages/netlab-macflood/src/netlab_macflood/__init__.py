# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-macflood - MAC flooding (CAM overflow)."""

from netlab_macflood.__version__ import __version__
from netlab_macflood.portsec import SecurePort

__all__ = ["SecurePort", "__version__"]
