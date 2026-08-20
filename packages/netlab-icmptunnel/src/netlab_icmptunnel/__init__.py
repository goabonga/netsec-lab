# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-icmptunnel - ICMP tunneling."""

from netlab_icmptunnel.__version__ import __version__
from netlab_icmptunnel.tunnel import decode, encode

__all__ = ["__version__", "decode", "encode"]
