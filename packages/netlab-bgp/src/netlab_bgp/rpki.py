# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""BGP origin-validation simulator (RPKI/ROA): the flagship lab in pure logic.

An AS announces the prefixes it originates; routers prefer the most specific /
shortest AS-path. Without origin authentication an AS can announce a prefix it
does not own - or a more specific sub-prefix - and draw the traffic to itself.
RPKI/ROA validates the origin AS against a signed authorization and drops the
invalid announcement. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass(frozen=True)
class Announcement:
    prefix: str
    origin_as: int
    as_path: tuple[int, ...] = ()


@dataclass
class Bgp:
    roas: dict[str, int] = field(default_factory=dict)  # prefix -> authorized origin AS

    def validate(self, ann: Announcement) -> str:
        """Return 'valid', 'invalid' or 'unknown' per RPKI origin validation."""
        auth = self.roas.get(ann.prefix)
        if auth is None:
            return "unknown"
        return "valid" if ann.origin_as == auth else "invalid"

    def accept(self, ann: Announcement, rpki: bool = False) -> bool:
        """Return True if the announcement is installed, False if RPKI drops it."""
        state = self.validate(ann)
        if rpki and state == "invalid":
            verdict("DROP", f"{ann.prefix} from AS{ann.origin_as}: RPKI invalid -> HIJACK BLOCKED")
            return False
        if state == "invalid":
            verdict(
                "ALERT", f"{ann.prefix} from AS{ann.origin_as}: wrong origin -> HIJACK ACCEPTED"
            )
        else:
            verdict("FORWARD", f"{ann.prefix} from AS{ann.origin_as} ({state})")
        return True


def demo() -> None:
    """Reference scenario: AS64666 hijacks AS64500's prefix, with and without RPKI."""
    bgp = Bgp(roas={"192.0.2.0/24": 64500})
    hijack = Announcement(prefix="192.0.2.0/24", origin_as=64666, as_path=(64666,))
    print("--- 1) no RPKI: the hijack is accepted ---")
    bgp.accept(hijack, rpki=False)
    print("\n--- 2) RPKI origin validation: the hijack is dropped ---")
    bgp.accept(hijack, rpki=True)
