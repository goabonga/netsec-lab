# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-icmp - ICMP redirect & tunneling."""

from netlab_icmp.__version__ import __version__
from netlab_icmp.redirect import RedirectPolicy

__all__ = ["RedirectPolicy", "__version__"]
