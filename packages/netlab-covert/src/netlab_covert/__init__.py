# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-covert - Covert channels."""

from netlab_covert.__version__ import __version__
from netlab_covert.channel import decode, encode, normalize

__all__ = ["__version__", "decode", "encode", "normalize"]
