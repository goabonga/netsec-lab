# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-tap - Passive network tapping."""

from netlab_tap.__version__ import __version__
from netlab_tap.exposure import TappedLink

__all__ = ["TappedLink", "__version__"]
