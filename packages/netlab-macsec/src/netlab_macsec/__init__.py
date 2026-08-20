# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-macsec - MACsec / MKA."""

from netlab_macsec.__version__ import __version__
from netlab_macsec.link import MacsecLink

__all__ = ["MacsecLink", "__version__"]
