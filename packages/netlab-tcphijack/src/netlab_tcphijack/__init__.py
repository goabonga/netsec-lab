# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-tcphijack - TCP session hijacking."""

from netlab_tcphijack.__version__ import __version__
from netlab_tcphijack.session import TcpSession

__all__ = ["TcpSession", "__version__"]
