# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-dns - DNS spoofing / cache poisoning."""

from netlab_dns.__version__ import __version__
from netlab_dns.resolver import Query, Resolver

__all__ = ["Query", "Resolver", "__version__"]
