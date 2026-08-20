# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-kerberos-net - Kerberos on the wire."""

from netlab_kerberos_net.__version__ import __version__
from netlab_kerberos_net.enctype import is_crackable

__all__ = ["__version__", "is_crackable"]
