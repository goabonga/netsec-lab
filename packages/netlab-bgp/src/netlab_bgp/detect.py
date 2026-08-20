# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detection side of netlab-bgp: RPKI origin validation of an announcement."""

from __future__ import annotations

import argparse

from netlab_core import verdict

from netlab_bgp.rpki import Announcement, Bgp


def run(args: argparse.Namespace) -> int:
    bgp = Bgp(roas={args.prefix: args.owner_as})
    state = bgp.validate(Announcement(prefix=args.prefix, origin_as=args.origin_as))
    if state == "invalid":
        verdict("ALERT", f"{args.prefix} from AS{args.origin_as}: RPKI INVALID -> hijack")
    else:
        verdict("FORWARD", f"{args.prefix} from AS{args.origin_as}: {state}")
    return 0
