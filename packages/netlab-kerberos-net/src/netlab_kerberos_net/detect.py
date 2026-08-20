# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-kerberos-net: flag legacy Kerberos encryption types."""

from __future__ import annotations

import argparse

from netlab_core import verdict

from netlab_kerberos_net.enctype import is_crackable


def run(args: argparse.Namespace) -> int:
    for enctype in args.enctypes:
        if is_crackable(enctype):
            verdict("ALERT", f"weak Kerberos enctype in use: {enctype} -> offline-crackable")
        else:
            verdict("FORWARD", f"strong enctype: {enctype}")
    return 0
