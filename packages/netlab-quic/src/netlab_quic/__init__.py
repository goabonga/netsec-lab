# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-quic - QUIC / HTTP3 fingerprinting."""

from netlab_quic.__version__ import __version__
from netlab_quic.header import classify, is_long_header

__all__ = ["__version__", "classify", "is_long_header"]
