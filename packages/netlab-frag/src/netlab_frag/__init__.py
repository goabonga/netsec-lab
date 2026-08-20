# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-frag - Fragmentation & IDS evasion."""

from netlab_frag.__version__ import __version__
from netlab_frag.reassembly import Fragment, reassemble

__all__ = ["Fragment", "__version__", "reassemble"]
