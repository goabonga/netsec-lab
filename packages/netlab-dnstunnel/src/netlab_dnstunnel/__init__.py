# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-dnstunnel - DNS tunneling."""

from netlab_dnstunnel.__version__ import __version__
from netlab_dnstunnel.tunnel import decode, encode, label_entropy

__all__ = ["__version__", "decode", "encode", "label_entropy"]
