# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Isolated-lab helpers: network namespaces + veth pairs.

Lets every PoC be replayed on a virtual L2 segment, with no hardware and no
leak off the host. Requires root (the `ip` commands).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


def _ip(*args: str) -> None:
    subprocess.run(["ip", *args], check=True)  # noqa: S603,S607


@dataclass
class VethLab:
    """A veth pair linking the host to an "attacker" namespace.

    Context manager: `with VethLab() as lab:` builds the segment and tears it
    down on exit. Serves as the isolated test segment for the PoC.
    """

    ns: str = "attacker"
    host_if: str = "veth-host"
    ns_if: str = "veth-ns"

    def __enter__(self) -> VethLab:
        _ip("netns", "add", self.ns)
        _ip("link", "add", self.host_if, "type", "veth", "peer", "name", self.ns_if)
        _ip("link", "set", self.ns_if, "netns", self.ns)
        _ip("link", "set", self.host_if, "up")
        _ip("netns", "exec", self.ns, "ip", "link", "set", self.ns_if, "up")
        return self

    def __exit__(self, *exc: object) -> None:
        # Deleting the namespace also removes the veth attached to it.
        subprocess.run(["ip", "netns", "del", self.ns], check=False)  # noqa: S603,S607
