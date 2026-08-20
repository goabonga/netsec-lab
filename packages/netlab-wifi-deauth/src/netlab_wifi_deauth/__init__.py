# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""netlab-wifi-deauth - 802.11 deauthentication."""

from netlab_wifi_deauth.__version__ import __version__
from netlab_wifi_deauth.pmf import Association

__all__ = ["Association", "__version__"]
