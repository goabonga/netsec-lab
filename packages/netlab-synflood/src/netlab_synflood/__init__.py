# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-synflood - TCP SYN flood."""

from netlab_synflood.__version__ import __version__
from netlab_synflood.backlog import TcpListener

__all__ = ["TcpListener", "__version__"]
