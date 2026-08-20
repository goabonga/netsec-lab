# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-tls: simulate an SSL-strip downgrade.

A real SSL strip runs as an on-path proxy rewriting HTTPS links to HTTP; this
models the outcome so you can see HSTS defeat it. Deploying it for real needs a
MITM position (e.g. after ARP spoofing); HSTS (see strip.py) is the fix.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict

from netlab_tls.strip import Browser


def run(args: argparse.Namespace) -> int:
    scheme = Browser(hsts=args.hsts).navigate("http")
    verdict("ALERT" if scheme == "http" else "INFO", f"victim ended up on {scheme}")
    return 0
