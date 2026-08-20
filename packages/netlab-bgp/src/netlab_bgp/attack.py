# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-bgp: simulate a prefix hijack in a lab AS mesh.

BGP hijacking needs a real peering session and the global routing table, so this
module models it in-process: it announces a victim prefix from a wrong origin AS
and shows the announcement being accepted when RPKI is off. RPKI/ROA (see
rpki.py) rejects it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict

from netlab_bgp.rpki import Announcement, Bgp


def run(args: argparse.Namespace) -> int:
    bgp = Bgp(roas={args.prefix: args.owner_as})
    hijack = Announcement(prefix=args.prefix, origin_as=args.hijack_as, as_path=(args.hijack_as,))
    print(f"[*] AS{args.hijack_as} announces {args.prefix} (owned by AS{args.owner_as})")
    accepted = bgp.accept(hijack, rpki=args.rpki)
    verdict("ALERT" if accepted and not args.rpki else "INFO", f"hijack accepted={accepted}")
    return 0
