# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-ipspoof - IP spoofing."""

from netlab_ipspoof.__version__ import __version__
from netlab_ipspoof.urpf import IngressFilter

__all__ = ["IngressFilter", "__version__"]
