# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-tls - TLS downgrade / MITM."""

from netlab_tls.__version__ import __version__
from netlab_tls.strip import Browser

__all__ = ["Browser", "__version__"]
