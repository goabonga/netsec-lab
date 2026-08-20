# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-ntp - NTP time-shift MITM."""

from netlab_ntp.__version__ import __version__
from netlab_ntp.clock import NtpClient

__all__ = ["NtpClient", "__version__"]
