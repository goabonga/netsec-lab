# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Capture wrapper: scapy is imported lazily so the package imports (and the
tests run) without scapy or root privileges.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def load_scapy() -> Any:
    """Import scapy.all on demand, with a clear message otherwise."""
    try:
        import scapy.all as scapy  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SystemExit("scapy missing -> `uv sync` or `pip install scapy`") from exc
    return scapy


def sniff(iface: str, bpf: str, handler: Callable[[Any], None]) -> None:
    """Sniff `iface` with a BPF filter, calling `handler` per packet."""
    scapy = load_scapy()
    scapy.sniff(iface=iface, filter=bpf, prn=handler, store=0)
