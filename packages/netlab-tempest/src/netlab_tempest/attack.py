# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-tempest: model an emanation-eavesdropping attempt.

A real attack captures electromagnetic emanations with an SDR and antenna; this
models the link budget so you can see at what distance / shielding reconstruction
succeeds. Requires an SDR to do for real; not replayable in the netns lab.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict

from netlab_tempest.emanation import reconstructable


def run(args: argparse.Namespace) -> int:
    ok = reconstructable(args.emission, args.distance, args.shielding)
    verdict(
        "ALERT" if ok else "INFO",
        f"reconstructable at {args.distance} m through {args.shielding} dB shielding: {ok}",
    )
    return 0
