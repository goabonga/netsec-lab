# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-amplif - Reflection & amplification."""

from netlab_amplif.__version__ import __version__
from netlab_amplif.factor import Reflector, measure

__all__ = ["Reflector", "__version__", "measure"]
