# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Fragment-reassembly simulator: the Ptacek-Newsham insertion/evasion core.

When fragments overlap, different stacks keep different bytes (first-wins vs
last-wins). If an IDS reassembles with one policy and the host with the other,
the attacker shows the IDS one payload and the host another. A normalizer that
drops overlapping fragments removes the ambiguity. Pure logic - safe anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass(frozen=True)
class Fragment:
    offset: int
    data: bytes


def reassemble(
    frags: list[Fragment], prefer: str = "first", drop_overlap: bool = False
) -> bytes | None:
    """Reassemble fragments. prefer='first'|'last' on overlap; drop_overlap normalizes."""
    buf: dict[int, int] = {}
    overlap = False
    for f in sorted(frags, key=lambda x: x.offset):
        for i, b in enumerate(f.data):
            pos = f.offset + i
            if pos in buf:
                overlap = True
                if drop_overlap:
                    return None
                if prefer == "last":
                    buf[pos] = b
            else:
                buf[pos] = b
    if overlap and not drop_overlap:
        verdict("INFO", f"overlapping fragments reassembled ({prefer}-wins)")
    return bytes(buf[p] for p in sorted(buf))


def demo() -> None:
    """Reference scenario: overlapping fragments an IDS and a host read differently."""
    frags = [Fragment(0, b"GET /public "), Fragment(4, b"/secret")]
    ids_view = reassemble(frags, prefer="first")
    host_view = reassemble(frags, prefer="last")
    print(f"IDS  sees (first-wins): {ids_view!r}")
    print(f"host sees (last-wins) : {host_view!r}")
    if ids_view != host_view:
        verdict("ALERT", "IDS and host disagree -> EVASION")
    print("\n--- normalizer drops overlapping fragments ---")
    normalized = reassemble(frags, drop_overlap=True)
    verdict("DROP" if normalized is None else "FORWARD", "overlap normalized")
