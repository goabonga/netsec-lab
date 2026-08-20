# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-ids-evasion - NIDS evasion (insertion/evasion)."""

from netlab_ids_evasion.__version__ import __version__
from netlab_ids_evasion.stream import Segment, reconstruct

__all__ = ["Segment", "__version__", "reconstruct"]
